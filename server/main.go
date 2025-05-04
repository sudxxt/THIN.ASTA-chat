package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type Client struct {
	conn     *websocket.Conn
	username string
	room     string
	color    string
	password string
	aesgcm   cipher.AEAD
	nonce    []byte
	ignores  map[string]bool
}

type Room struct {
	name    string
	clients map[*Client]bool
	created time.Time
	locked  bool
	pass    string
	topic   string
	history []string
}

var (
	clients    = make(map[*Client]bool)
	rooms      = make(map[string]*Room)
	mu         sync.Mutex
	db         *sql.DB
	colors     = []string{"\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m"}
	colorIndex = 0
)

func initDB() {
	var err error
	os.Remove("chat.db")
	db, err = sql.Open("sqlite", "file:chat.db?_foreign_keys=1")
	if err != nil {
		log.Fatal("DB error:", err)
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password TEXT NOT NULL,
		color TEXT
	);
	CREATE TABLE IF NOT EXISTS rooms (
		name TEXT PRIMARY KEY,
		password TEXT,
		created TIMESTAMP,
		locked BOOLEAN
	)`)
	if err != nil {
		log.Fatal("DB init error:", err)
	}

	db.Exec("INSERT OR IGNORE INTO rooms (name, created, locked) VALUES ('general', datetime('now'), 0)")
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "localhost"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "localhost"
}

func showWelcome() {
	fmt.Println(`reChat - A simple chat server`)
}

func setupEncryption(password string) (cipher.AEAD, []byte, error) {
	hash := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	return aesgcm, nonce, nil
}

func decryptMessage(aesgcm cipher.AEAD, nonce []byte, msg string) (string, error) {
	if aesgcm == nil {
		return msg, nil
	}
	data, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		return msg, nil
	}
	plaintext, err := aesgcm.Open(nil, nonce, data, nil)
	if err != nil {
		return msg, nil
	}
	return string(plaintext), nil
}

func encryptMessage(aesgcm cipher.AEAD, nonce []byte, msg string) (string, error) {
	if aesgcm == nil {
		return msg, nil
	}
	ciphertext := aesgcm.Seal(nil, nonce, []byte(msg), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func sendSystemMessage(client *Client, msg string) {
	encMsg, _ := encryptMessage(client.aesgcm, client.nonce, "\033[1;37m"+msg+"\033[0m")
	client.conn.WriteMessage(websocket.TextMessage, []byte(encMsg))
}

func broadcast(msg string, sender *Client, isSystem bool) {
	mu.Lock()
	defer mu.Unlock()

	rObj, exists := rooms[sender.room]
	if !exists {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	var logMsg string
	if isSystem {
		logMsg = fmt.Sprintf("[%s] %s", timestamp, msg)
	} else {
		// Корректно выделяем ник даже если он содержит русские символы
		coloredMsg := msg
		if strings.HasPrefix(msg, sender.username+":") {
			coloredMsg = sender.color + sender.username + "\033[0m:" + msg[len(sender.username)+1:]
		}
		logMsg = fmt.Sprintf("[%s] %s", timestamp, coloredMsg)
	}

	if !isSystem {
		if len(rObj.history) >= 50 {
			rObj.history = rObj.history[1:]
		}
		rObj.history = append(rObj.history, logMsg)
	}

	for client := range rObj.clients {
		if !isSystem && client.ignores != nil && client.ignores[sender.username] {
			continue
		}
		outMsg := logMsg
		if isSystem {
			outMsg = "\033[1;37m" + logMsg + "\033[0m"
		}
		encMsg, _ := encryptMessage(client.aesgcm, client.nonce, outMsg)
		client.conn.WriteMessage(websocket.TextMessage, []byte(encMsg))
	}
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket error:", err)
		return
	}
	defer conn.Close()

	remoteAddr := r.RemoteAddr

	_, msg, err := conn.ReadMessage()
	if err != nil {
		log.Println("Auth read error:", err)
		return
	}

	parts := strings.SplitN(string(msg), ":", 4)
	if len(parts) < 3 {
		conn.WriteMessage(websocket.TextMessage, []byte("ERROR: Use username:password:room[:roompass]"))
		return
	}

	username, password, room := parts[0], parts[1], parts[2]
	var roomPass string
	if len(parts) > 3 {
		roomPass = parts[3]
	}

	// Логирование подключения
	log.Printf("New connection: IP=%s, Username=%s, Room=%s, Time=%s", remoteAddr, username, room, time.Now().Format("2006-01-02 15:04:05"))

	var storedPassword, storedColor string
	err = db.QueryRow("SELECT password, color FROM users WHERE username = ?", username).Scan(&storedPassword, &storedColor)

	if err == nil {
		if storedPassword != password {
			conn.WriteMessage(websocket.TextMessage, []byte("ERROR: Wrong password"))
			return
		}
	} else {
		color := colors[colorIndex%len(colors)]
		colorIndex++
		_, err = db.Exec("INSERT INTO users (username, password, color) VALUES (?, ?, ?)", username, password, color)
		if err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte("ERROR: Registration failed - "+err.Error()))
			return
		}
		storedColor = color
	}

	aesgcm, nonce, err := setupEncryption(password)
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte("ERROR: Encryption setup failed"))
		return
	}

	mu.Lock()
	rObj, exists := rooms[room]
	if !exists {
		rObj = &Room{
			name:    room,
			clients: make(map[*Client]bool),
			created: time.Now(),
			locked:  roomPass != "",
			pass:    roomPass,
			history: []string{},
		}
		rooms[room] = rObj
		db.Exec("INSERT INTO rooms (name, password, created, locked) VALUES (?, ?, datetime('now'), ?)", room, roomPass, rObj.locked)
	} else if rObj.locked && rObj.pass != roomPass {
		mu.Unlock()
		conn.WriteMessage(websocket.TextMessage, []byte("ERROR: Wrong room password"))
		return
	}
	mu.Unlock()

	client := &Client{
		conn:     conn,
		username: username,
		room:     room,
		color:    storedColor,
		password: password,
		aesgcm:   aesgcm,
		nonce:    nonce,
		ignores:  make(map[string]bool),
	}

	mu.Lock()
	clients[client] = true
	rObj.clients[client] = true
	mu.Unlock()

	mu.Lock()
	if len(rObj.history) > 0 {
		for _, hist := range rObj.history {
			encMsg, _ := encryptMessage(client.aesgcm, client.nonce, "\033[2m"+hist+"\033[0m")
			client.conn.WriteMessage(websocket.TextMessage, []byte(encMsg))
		}
	}
	mu.Unlock()

	if rObj.topic != "" {
		sendSystemMessage(client, "Room topic: "+rObj.topic)
	}

	sendSystemMessage(client, fmt.Sprintf("Welcome to '%s', %s! Members: %d", room, username, len(rObj.clients)))
	sendSystemMessage(client, "Type /help for commands list")
	broadcast(fmt.Sprintf("%s joined", username), client, true)

	typingChan := make(chan bool, 1)
	go handleTyping(client, typingChan)

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			mu.Lock()
			delete(clients, client)
			if rObj, ok := rooms[room]; ok {
				delete(rObj.clients, client)
				if len(rObj.clients) == 0 && room != "general" {
					delete(rooms, room)
					db.Exec("DELETE FROM rooms WHERE name = ?", room)
				}
			}
			mu.Unlock()
			broadcast(fmt.Sprintf("%s left", username), client, true)
			return
		}

		msg := strings.TrimSpace(string(message))

		if msg == "__TYPING__" {
			typingChan <- true
			continue
		}

		if !strings.HasPrefix(msg, "/") {
			plain, _ := decryptMessage(client.aesgcm, client.nonce, msg)
			msg = plain
		}

		handleCommand(client, msg)
	}
}

func handleTyping(client *Client, typingChan <-chan bool) {
	for range typingChan {
		mu.Lock()
		rObj, exists := rooms[client.room]
		mu.Unlock()
		if !exists {
			return
		}
		for c := range rObj.clients {
			if c == client {
				continue
			}
			encMsg, _ := encryptMessage(c.aesgcm, c.nonce, fmt.Sprintf("\033[36m%s печатает...\033[0m", client.username))
			c.conn.WriteMessage(websocket.TextMessage, []byte(encMsg))
		}
	}
}

func handleCommand(client *Client, msg string) {
	cmd := strings.Fields(msg)
	if len(cmd) == 0 {
		return
	}

	switch cmd[0] {
	case "/exit":
		return
	case "/help":
		sendHelp(client)
	case "/list":
		sendRoomList(client)
	case "/who":
		sendUserList(client)
	case "/nick":
		if len(cmd) < 2 {
			sendSystemMessage(client, "ERROR: Use /nick newname")
			return
		}
		// Поддержка русских символов в нике
		changeNickname(client, strings.Join(cmd[1:], " "))
	case "/create":
		if len(cmd) < 2 {
			sendSystemMessage(client, "ERROR: Use /create room [password]")
			return
		}
		createRoom(client, strings.Join(cmd[1:], " "))
	case "/delete":
		if len(cmd) < 2 {
			sendSystemMessage(client, "ERROR: Use /delete room")
			return
		}
		deleteRoom(client, strings.Join(cmd[1:], " "))
	case "/lock":
		if len(cmd) < 2 {
			sendSystemMessage(client, "ERROR: Use /lock password")
			return
		}
		lockRoom(client, strings.Join(cmd[1:], " "))
	case "/unlock":
		unlockRoom(client)
	case "/msg":
		if len(cmd) < 3 {
			sendSystemMessage(client, "ERROR: Use /msg user message")
			return
		}
		sendPrivateMessage(client, strings.Join(cmd[1:], " "))
	case "/me":
		if len(cmd) < 2 {
			sendSystemMessage(client, "ERROR: Use /me action")
			return
		}
		// Поддержка русских символов в действиях
		broadcast(fmt.Sprintf("* %s %s", client.username, strings.Join(cmd[1:], " ")), client, false)
	case "/topic":
		if len(cmd) < 2 {
			showTopic(client)
			return
		}
		setTopic(client, strings.Join(cmd[1:], " "))
	case "/ignore":
		if len(cmd) < 2 {
			sendSystemMessage(client, "ERROR: Use /ignore username")
			return
		}
		ignoreUser(client, cmd[1])
	case "/unignore":
		if len(cmd) < 2 {
			sendSystemMessage(client, "ERROR: Use /unignore username")
			return
		}
		unignoreUser(client, cmd[1])
	case "/roll":
		rollDice(client, cmd[1:])
	case "/psycho":
		// Рассылаем команду всем клиентам комнаты
		mu.Lock()
		rObj, exists := rooms[client.room]
		mu.Unlock()
		if exists {
			for c := range rObj.clients {
				c.conn.WriteMessage(websocket.TextMessage, []byte("/psycho"))
			}
		}
	case "/blackout":
		// Если есть текст после /blackout, рассылаем его всем клиентам комнаты
		joke := strings.TrimPrefix(msg, "/blackout")
		joke = strings.TrimSpace(joke)
		if joke != "" {
			mu.Lock()
			rObj, exists := rooms[client.room]
			mu.Unlock()
			if exists {
				for c := range rObj.clients {
					c.conn.WriteMessage(websocket.TextMessage, []byte("/blackout "+joke))
				}
			}
		}
		return
	default:
		// Поддержка русских символов в обычных сообщениях
		broadcast(fmt.Sprintf("%s: %s", client.username, msg), client, false)
	}
}

func showTopic(client *Client) {
	mu.Lock()
	defer mu.Unlock()
	rObj, exists := rooms[client.room]
	if !exists {
		sendSystemMessage(client, "ERROR: Room not found")
		return
	}
	if rObj.topic == "" {
		sendSystemMessage(client, "No topic set for this room.")
	} else {
		sendSystemMessage(client, "Room topic: "+rObj.topic)
	}
}

func setTopic(client *Client, topic string) {
	mu.Lock()
	defer mu.Unlock()
	rObj, exists := rooms[client.room]
	if !exists {
		sendSystemMessage(client, "ERROR: Room not found")
		return
	}
	rObj.topic = topic
	broadcast(fmt.Sprintf("Room topic set to: %s", topic), client, true)
}

func ignoreUser(client *Client, username string) {
	client.ignores[username] = true
	sendSystemMessage(client, fmt.Sprintf("You are now ignoring %s", username))
}

func unignoreUser(client *Client, username string) {
	delete(client.ignores, username)
	sendSystemMessage(client, fmt.Sprintf("You are no longer ignoring %s", username))
}

func rollDice(client *Client, args []string) {
	max := 100
	if len(args) > 0 {
		n, err := strconv.Atoi(args[0])
		if err == nil && n > 1 && n <= 1000000 {
			max = n
		}
	}
	result := rand.Intn(max) + 1
	broadcast(fmt.Sprintf("%s rolled a %d (1-%d)", client.username, result, max), client, true)
}

func sendHelp(client *Client) {
	helpMsg := `COMMANDS:
/help - Show this help
/list - List rooms
/who - List room members
/nick <newname> - Change nickname
/msg <user> <message> - Private message
/me <action> - Third-person action
/create <room> [password] - Create room
/delete <room> - Delete room
/lock <password> - Lock room
/unlock - Unlock room
/topic [text] - Show or set room topic
/ignore <user> - Ignore user
/unignore <user> - Stop ignoring user
/roll [max] - Roll a dice (default 1-100)
/exit - Exit chat`
	sendSystemMessage(client, helpMsg)
}

func sendRoomList(client *Client) {
	mu.Lock()
	defer mu.Unlock()

	var roomList strings.Builder
	roomList.WriteString("Available rooms:\n")
	for name, room := range rooms {
		roomList.WriteString(fmt.Sprintf("- %s (members: %d, created: %s", name, len(room.clients), room.created.Format("15:04")))
		if room.locked {
			roomList.WriteString(", 🔒")
		}
		roomList.WriteString("\n")
	}
	sendSystemMessage(client, roomList.String())
}

func sendUserList(client *Client) {
	mu.Lock()
	defer mu.Unlock()

	rObj, exists := rooms[client.room]
	if !exists {
		sendSystemMessage(client, "ERROR: Room not found")
		return
	}

	var userList strings.Builder
	userList.WriteString(fmt.Sprintf("Members in '%s':\n", client.room))
	for c := range rObj.clients {
		userList.WriteString(fmt.Sprintf("- %s\n", c.username))
	}
	sendSystemMessage(client, userList.String())
}

func changeNickname(client *Client, newNick string) {
	mu.Lock()
	defer mu.Unlock()

	newNick = strings.TrimSpace(newNick)
	if newNick == "" {
		sendSystemMessage(client, "ERROR: Empty nickname")
		return
	}

	for c := range clients {
		if c.username == newNick {
			sendSystemMessage(client, "ERROR: Nickname taken")
			return
		}
	}

	oldNick := client.username
	client.username = newNick

	_, err := db.Exec("UPDATE users SET username = ? WHERE username = ?", newNick, oldNick)
	if err != nil {
		sendSystemMessage(client, "ERROR: Nick change failed - "+err.Error())
		return
	}

	broadcast(fmt.Sprintf("%s renamed to %s", oldNick, newNick), client, true)
}

func createRoom(client *Client, args string) {
	parts := strings.SplitN(args, " ", 2)
	roomName := strings.TrimSpace(parts[0])
	var roomPass string
	if len(parts) > 1 {
		roomPass = strings.TrimSpace(parts[1])
	}

	if roomName == "" {
		sendSystemMessage(client, "ERROR: Room name required")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := rooms[roomName]; exists {
		sendSystemMessage(client, "ERROR: Room exists")
		return
	}

	rooms[roomName] = &Room{
		name:    roomName,
		clients: make(map[*Client]bool),
		created: time.Now(),
		locked:  roomPass != "",
		pass:    roomPass,
		history: []string{},
	}

	db.Exec("INSERT INTO rooms (name, password, created, locked) VALUES (?, ?, datetime('now'), ?)", roomName, roomPass, roomPass != "")
	sendSystemMessage(client, fmt.Sprintf("Room '%s' created", roomName))
}

func deleteRoom(client *Client, roomName string) {
	roomName = strings.TrimSpace(roomName)
	if roomName == "" {
		sendSystemMessage(client, "ERROR: Room name required")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	rObj, exists := rooms[roomName]
	if !exists {
		sendSystemMessage(client, "ERROR: Room not found")
		return
	}

	if roomName == "general" {
		sendSystemMessage(client, "ERROR: Cannot delete general")
		return
	}

	for c := range rObj.clients {
		c.room = "general"
		rooms["general"].clients[c] = true
		sendSystemMessage(c, fmt.Sprintf("Room '%s' deleted, moved to general", roomName))
	}

	delete(rooms, roomName)
	db.Exec("DELETE FROM rooms WHERE name = ?", roomName)
	broadcast(fmt.Sprintf("Room '%s' was deleted", roomName), client, true)
}

func lockRoom(client *Client, password string) {
	password = strings.TrimSpace(password)
	if password == "" {
		sendSystemMessage(client, "ERROR: Password required")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	rObj, exists := rooms[client.room]
	if !exists {
		sendSystemMessage(client, "ERROR: Room not found")
		return
	}

	rObj.locked = true
	rObj.pass = password
	db.Exec("UPDATE rooms SET locked = 1, password = ? WHERE name = ?", password, client.room)
	sendSystemMessage(client, fmt.Sprintf("Room '%s' locked", client.room))
	broadcast("Room is now locked", client, true)
}

func unlockRoom(client *Client) {
	mu.Lock()
	defer mu.Unlock()

	rObj, exists := rooms[client.room]
	if !exists {
		sendSystemMessage(client, "ERROR: Room not found")
		return
	}

	rObj.locked = false
	rObj.pass = ""
	db.Exec("UPDATE rooms SET locked = 0, password = '' WHERE name = ?", client.room)
	sendSystemMessage(client, fmt.Sprintf("Room '%s' unlocked", client.room))
	broadcast("Room is now unlocked", client, true)
}

func sendPrivateMessage(client *Client, args string) {
	parts := strings.SplitN(args, " ", 2)
	if len(parts) < 2 {
		sendSystemMessage(client, "ERROR: Use /msg user message")
		return
	}

	targetNick := strings.TrimSpace(parts[0])
	message := strings.TrimSpace(parts[1])

	mu.Lock()
	defer mu.Unlock()

	var found bool
	for c := range clients {
		if c.username == targetNick {
			found = true
			msg := fmt.Sprintf("\033[35m[PM from %s] %s\033[0m", client.username, message)
			encMsg, _ := encryptMessage(c.aesgcm, c.nonce, msg)
			c.conn.WriteMessage(websocket.TextMessage, []byte(encMsg))
			selfMsg := fmt.Sprintf("\033[35m[PM to %s] %s\033[0m", targetNick, message)
			selfEnc, _ := encryptMessage(client.aesgcm, client.nonce, selfMsg)
			client.conn.WriteMessage(websocket.TextMessage, []byte(selfEnc))
			break
		}
	}

	if !found {
		sendSystemMessage(client, fmt.Sprintf("ERROR: User '%s' not found", targetNick))
	}
}

func main() {
	showWelcome()
	initDB()
	defer db.Close()

	fmt.Println("\nВыберите режим сервера:")
	fmt.Println("1 - Локальный (только этот компьютер)")
	fmt.Println("2 - Удалённый (доступ из интернета)")
	fmt.Print("Ваш выбор: ")

	var mode int
	fmt.Scanln(&mode)

	ip := "localhost"
	if mode == 2 {
		ip = getLocalIP()
		fmt.Printf("\nАдрес сервера: http://%s:8080\n", ip)
		fmt.Println("\nДля доступа из интернета:")
		fmt.Println("1. Установите ngrok (https://ngrok.com/download)")
		fmt.Println("2. Запустите: ngrok http 8080")
		fmt.Println("3. Поделитесь ссылкой ngrok (например, https://XXXX.ngrok.io)")
	}

	rooms["general"] = &Room{
		name:    "general",
		clients: make(map[*Client]bool),
		created: time.Now(),
		locked:  false,
		history: []string{},
	}

	http.HandleFunc("/ws", handleConnections)
	log.Printf("Сервер запущен на %s:8080", ip)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
