package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/gorilla/websocket"
)

var (
	conn       *websocket.Conn
	aesgcm     cipher.AEAD
	nonce      []byte
	ignoreList = make(map[string]bool)
	screen     tcell.Screen
	inputField = ""
	inputPos   = 0
	messages   []string
	showHelp   = false
	nickColors = []tcell.Color{
		tcell.ColorLightCyan, tcell.ColorMediumPurple, tcell.ColorLightGreen,
		tcell.ColorLightBlue, tcell.ColorLightYellow, tcell.ColorRed,
	}
	nickColorMap = make(map[string]tcell.Color)
	clownMap     = make(map[string]time.Time)
	clownMutex   sync.Mutex
	matrixMode   = false
	scrollOffset = 0
)

func showWelcome() {
	welcome := `к нам пришел`
	fmt.Println(welcome)
	fmt.Println("Добро пожаловать в чат! Нажмите F1 для справки, Ctrl+C или введите /exit для выхода")
}

func normalizeAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.TrimPrefix(addr, "https://")

	if !strings.HasPrefix(addr, "ws://") && !strings.HasPrefix(addr, "wss://") {
		if strings.Contains(addr, "ngrok.io") {
			addr = "wss://" + addr
		} else {
			addr = "ws://" + addr
		}
	}

	if !strings.Contains(addr, "/ws") {
		addr += "/ws"
	}

	return addr
}

func connectToServer() error {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\nВыберите тип подключения:")
		fmt.Println("1 - Локальный сервер (localhost)")
		fmt.Println("2 - Удаленный сервер (через интернет)")
		fmt.Print("Ваш выбор: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		var serverAddr string

		switch choice {
		case "1":
			serverAddr = "ws://localhost:8080/ws"
		case "2":
			fmt.Print("Введите адрес сервера (например: wss://xxxx.ngrok.io): ")
			addr, _ := reader.ReadString('\n')
			serverAddr = normalizeAddress(addr)
		default:
			fmt.Println("Неправильный выбор, попробуйте еще раз")
			continue
		}

		fmt.Printf("\nПопытка подключения к %s...\n", serverAddr)

		var err error
		conn, _, err = websocket.DefaultDialer.Dial(serverAddr, nil)
		if err == nil {
			fmt.Println("Подключение установлено!")
			return nil
		}

		fmt.Printf("\nОШИБКА: Не удалось подключиться (%v)\n", err)
		fmt.Println("Возможные причины:")
		fmt.Println("- Сервер не запущен")
		fmt.Println("- Неправильный адрес")
		fmt.Println("- Проблемы с сетью")
		fmt.Println("Попробуйте еще раз")
	}
}

func setupEncryption(password string) error {
	hash := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return err
	}
	aesgcmLocal, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	aesgcm = aesgcmLocal
	nonce = make([]byte, aesgcm.NonceSize())
	return nil
}

func encryptMessage(msg string) (string, error) {
	if aesgcm == nil {
		return msg, nil
	}
	ciphertext := aesgcm.Seal(nil, nonce, []byte(msg), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptMessage(msg string) (string, error) {
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

func authUser() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("\nВведите логин: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Введите пароль: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)
	setupEncryption(password)

	fmt.Print("Введите комнату [general]: ")
	room, _ := reader.ReadString('\n')
	room = strings.TrimSpace(room)
	if room == "" {
		room = "general"
	}

	authMsg := fmt.Sprintf("%s:%s:%s", username, password, room)
	return conn.WriteMessage(websocket.TextMessage, []byte(authMsg))
}

func initScreen() {
	var err error
	screen, err = tcell.NewScreen()
	if err != nil {
		log.Fatalf("%+v", err)
	}
	if err := screen.Init(); err != nil {
		log.Fatalf("%+v", err)
	}

	screen.SetStyle(tcell.StyleDefault.
		Foreground(tcell.ColorWhite).
		Background(tcell.ColorBlack))
	screen.Clear()
	screen.EnablePaste()
}

func drawScreen() {
	screen.Clear()
	w, h := screen.Size()

	// Цветовые стили
	infoStyle := tcell.StyleDefault.Foreground(tcell.ColorGreen)
	errorStyle := tcell.StyleDefault.Foreground(tcell.ColorRed)
	inputStyle := tcell.StyleDefault.Foreground(tcell.ColorYellow)
	messageStyle := tcell.StyleDefault.Foreground(tcell.ColorWhite)
	systemStyle := tcell.StyleDefault.Foreground(tcell.ColorBlue)
	helpStyle := tcell.StyleDefault.Foreground(tcell.ColorGreen).Background(tcell.ColorDarkBlue)

	// Плашка с текущим временем (часы:минуты)
	timeStr := time.Now().Format("15:04")
	timeStyle := tcell.StyleDefault.Foreground(tcell.ColorLightCyan).Background(tcell.ColorBlack)
	printStyled(w-len(timeStr)-2, 0, " "+timeStr+" ", timeStyle, w)

	if matrixMode {
		drawMatrix(w, h)
		return
	}

	if showHelp {
		drawHelp(w, h, helpStyle)
		return
	}

	// Рисуем историю сообщений
	maxRows := h - 3
	total := len(messages)
	if scrollOffset > total-maxRows {
		scrollOffset = total - maxRows
	}
	if scrollOffset < 0 {
		scrollOffset = 0
	}
	startRow := 0
	if total > maxRows {
		startRow = total - maxRows - scrollOffset
	}
	if startRow < 0 {
		startRow = 0
	}
	for i := startRow; i < total-scrollOffset; i++ {
		msg := messages[i]
		row := i - startRow

		style := messageStyle
		if strings.HasPrefix(msg, "ERROR:") {
			style = errorStyle
		} else if strings.HasPrefix(msg, "***") || strings.HasPrefix(msg, "[PM") {
			style = infoStyle
		} else if strings.HasPrefix(msg, "[SYSTEM]") {
			style = systemStyle
		}

		// Подсветка ников (до первого ':')
		colored := false
		if idx := strings.Index(msg, ":"); idx > 0 && idx < 32 {
			nick := stripColor(msg[:idx])
			clownMutex.Lock()
			clownUntil, clowned := clownMap[nick]
			clownMutex.Unlock()
			color := getNickColor(nick)
			if clowned && time.Now().Before(clownUntil) {
				color = tcell.ColorYellow
				nick = nick + " 🤡"
			}
			nickStyle := style.Foreground(color)
			printStyled(0, row, nick, nickStyle, w)
			printStyled(len(nick), row, msg[idx:], style, w)
			colored = true
		}
		if !colored {
			printStyled(0, row, msg, style, w)
		}
	}

	// Рисуем разделитель
	for x := 0; x < w; x++ {
		screen.SetContent(x, h-2, '─', nil, tcell.StyleDefault.Foreground(tcell.ColorGray))
	}

	// Рисуем поле ввода
	prompt := "> "
	printStyled(0, h-1, prompt, inputStyle, w)
	printStyled(len(prompt), h-1, inputField, inputStyle, w)

	// Позиция курсора (с учётом Unicode)
	cursorX := len(prompt) + runePosInString(inputField, inputPos)
	if cursorX >= w {
		cursorX = w - 1
	}
	screen.ShowCursor(cursorX, h-1)
	screen.Show()
}

func printStyled(x, y int, text string, style tcell.Style, maxWidth int) {
	col := x
	for _, r := range text {
		if col >= maxWidth {
			break
		}
		screen.SetContent(col, y, r, nil, style)
		col++
	}
}

func drawHelp(w, h int, style tcell.Style) {
	helpText := []string{
		"СПРАВКА ПО КОМАНДАМ\n",
		"F1 - Показать/скрыть справку\n",
		"/help - Показать эту справку\n",
		"/list - Список комнат\n",
		"/who - Список участников\n",
		"/nick <имя> - Сменить ник\n",
		"/msg <ник> <сообщение> - Личное сообщение\n",
		"/me <действие> - Действие от третьего лица\n",
		"/create <комната> [пароль] - Создать комнату\n",
		"/delete <комната> - Удалить комнату\n",
		"/lock <пароль> - Закрыть комнату паролем\n",
		"/unlock - Открыть комнату\n",
		"/topic [текст] - Показать/установить тему\n",
		"/ignore <ник> - Игнорировать пользователя\n",
		"/unignore <ник> - Прекратить игнорирование\n",
		"/roll [макс] - Бросить кости (по умолчанию 1-100)\n",
		"/exit - Выйти из чата\n",
		"/ascii <текст> - ASCII-арт через внешний API (figlet)\n",
		"/rainbow <текст> - Радужный текст\n",
		"/matrix - Анимация 'Матрицы'\n",
		"/clown <ник> - Помечает пользователя как клоуна на 1 минуту\n",
		"/scream - Крупное цветное 'AAAAAAAAAAAA!'\n",
		"/psycho - Психоделическая анимация на экране\n",
		"/geymini <вопрос> - Задать вопрос Gemini API\n",
		"/sendfile <путь> - Отправить файл через временный HTTP-сервер\n",
		"/blackout - Тёмная комната с шуткой от Gemini\n",
		"",
		"Нажмите F1 для закрытия справки\n",
	}

	for i, line := range helpText {
		if i >= h {
			break
		}
		printStyled(0, i, line, style, w)
	}
}

func handleInput() {
	for {
		ev := screen.PollEvent()
		switch ev := ev.(type) {
		case *tcell.EventKey:
			switch ev.Key() {
			case tcell.KeyEscape, tcell.KeyCtrlC:
				shutdown()
				return
			case tcell.KeyF1:
				showHelp = !showHelp
			case tcell.KeyEnter:
				if showHelp {
					showHelp = false
				} else {
					processInput()
				}
			case tcell.KeyBackspace, tcell.KeyBackspace2:
				if inputPos > 0 {
					// Удаляем предыдущий символ (Unicode)
					r, size := utf8.DecodeLastRuneInString(inputField[:inputPos])
					if r != utf8.RuneError {
						inputField = inputField[:inputPos-size] + inputField[inputPos:]
						inputPos -= size
					}
				}
			case tcell.KeyLeft:
				if inputPos > 0 {
					_, size := utf8.DecodeLastRuneInString(inputField[:inputPos])
					inputPos -= size
				}
			case tcell.KeyRight:
				if inputPos < len(inputField) {
					_, size := utf8.DecodeRuneInString(inputField[inputPos:])
					inputPos += size
				}
			case tcell.KeyPgUp, tcell.KeyUp:
				scrollOffset++
				drawScreen()
			case tcell.KeyPgDn, tcell.KeyDown:
				if scrollOffset > 0 {
					scrollOffset--
				}
				drawScreen()
			case tcell.KeyRune:
				if ev.Rune() != 0 {
					r := ev.Rune()
					buf := []rune(inputField)
					pos := runeIndexAtByte(inputField, inputPos)
					buf = append(buf[:pos], append([]rune{r}, buf[pos:]...)...)
					inputField = string(buf)
					inputPos += utf8.RuneLen(r)
				}
			}
			drawScreen()
		case *tcell.EventResize:
			drawScreen()
		}
	}
}

func processInput() {
	text := strings.TrimSpace(inputField)
	inputField = ""
	inputPos = 0
	drawScreen()

	if text == "" {
		return
	}

	// /ascii <текст>
	if strings.HasPrefix(text, "/ascii ") {
		go func() {
			asciiArt := getAsciiArt(strings.TrimSpace(strings.TrimPrefix(text, "/ascii")))
			// Выводим как одно сообщение, чтобы не было "выше вывод команды ascii"
			addMessage(asciiArt)
		}()
		return
	}

	// /rainbow <текст>
	if strings.HasPrefix(text, "/rainbow ") {
		rainbow := rainbowAnsi(strings.TrimSpace(strings.TrimPrefix(text, "/rainbow")))
		addMessage(rainbow)
		return
	}

	// /matrix
	if text == "/matrix" {
		matrixMode = true
		go runMatrix()
		return
	}

	// /clown <ник>
	if strings.HasPrefix(text, "/clown ") {
		nick := strings.TrimSpace(strings.TrimPrefix(text, "/clown"))
		clownMutex.Lock()
		clownMap[nick] = time.Now().Add(time.Minute)
		clownMutex.Unlock()
		addMessage(fmt.Sprintf("*** %s теперь клоун 🤡 на 1 минуту!", nick))
		return
	}

	// /scream
	if text == "/scream" {
		s := screamArt()
		for _, line := range strings.Split(s, "\n") {
			addMessage(line)
		}
		return
	}

	// Обработка команды /wether
	if text == "/wether" {
		go showWeatherAPI()
		return
	}

	// /geymini <вопрос>
	if strings.HasPrefix(text, "/geymini ") {
		question := strings.TrimSpace(strings.TrimPrefix(text, "/geymini"))
		addMessage("[Gemini] Запрос: " + question)
		go func() {
			answer := askGemini(question)
			msg := "[Gemini] " + question + ": " + answer
			addMessage(msg)
			if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
				addMessage("[Gemini] Ошибка отправки ответа: " + err.Error())
			}
		}()
		return
	}

	// Обработка команд ignore/unignore локально
	if strings.HasPrefix(text, "/ignore ") {
		user := strings.TrimSpace(strings.TrimPrefix(text, "/ignore"))
		ignoreList[user] = true
		addMessage(fmt.Sprintf("*** Теперь вы игнорируете %s", user))
		return
	}
	if strings.HasPrefix(text, "/unignore ") {
		user := strings.TrimSpace(strings.TrimPrefix(text, "/unignore"))
		delete(ignoreList, user)
		addMessage(fmt.Sprintf("*** Вы больше не игнорируете %s", user))
		return
	}

	// /psycho (отправляем команду на сервер, чтобы все увидели)
	if text == "/psycho" {
		if err := conn.WriteMessage(websocket.TextMessage, []byte("/psycho")); err != nil {
			addMessage("ERROR: Ошибка отправки команды /psycho")
		}
		return
	}

	// --- P2P File Sharing Command ---
	if strings.HasPrefix(text, "/sendfile ") {
		filePath := strings.TrimSpace(strings.TrimPrefix(text, "/sendfile"))
		addMessage("[FILE] Подготовка файла: " + filePath)
		go func() {
			url, _, err := startFileServer(filePath)
			if err != nil {
				addMessage("[FILE] Ошибка: " + err.Error())
				return
			}
			addMessage("[FILE] Ссылка для скачивания: " + url)
			// Можно отправить ссылку в чат для других
			if err := conn.WriteMessage(websocket.TextMessage, []byte("[FILE] "+url)); err != nil {
				addMessage("[FILE] Ошибка отправки ссылки: " + err.Error())
			}
		}()
		return
	}

	// /blackout — тёмная комната с шуткой от Gemini
	if text == "/blackout" {
		go func() {
			joke := askGemini("Расскажи очень чёрную, мрачную, но короткую шутку на русском языке. Не используй цензуру. Не добавляй пояснений. Только саму шутку.")
			cmd := "/blackout " + joke
			if err := conn.WriteMessage(websocket.TextMessage, []byte(cmd)); err != nil {
				addMessage("ERROR: Ошибка отправки blackout: " + err.Error())
			}
		}()
		return
	}

	var toSend string
	if strings.HasPrefix(text, "/") {
		toSend = text
	} else {
		enc, err := encryptMessage(text)
		if err != nil {
			addMessage(fmt.Sprintf("ERROR: Ошибка шифрования: %v", err))
			return
		}
		toSend = enc
	}

	if err := conn.WriteMessage(websocket.TextMessage, []byte(toSend)); err != nil {
		addMessage(fmt.Sprintf("ERROR: Ошибка отправки: %v", err))
		return
	}

	if text == "/exit" {
		shutdown()
	}
}

func addMessage(msg string) {
	const maxLineLen = 80
	lines := splitLongMessage(stripInvalidAnsi(msg), maxLineLen)
	messages = append(messages, lines...)
	if len(messages) > 100 {
		messages = messages[len(messages)-100:]
	}
	scrollOffset = 0
	drawScreen()
}

func stripInvalidAnsi(s string) string {
	// Оставляем только валидные ANSI последовательности
	result := strings.Builder{}
	inEscape := false
	escapeStart := 0

	for i, r := range s {
		if inEscape {
			if r >= 0x40 && r <= 0x7E { // Конец ANSI последовательности
				seq := s[escapeStart : i+1]
				if isValidAnsiSequence(seq) {
					result.WriteString(seq)
				}
				inEscape = false
			}
			continue
		}

		if r == '\x1b' {
			inEscape = true
			escapeStart = i
			continue
		}

		if !inEscape {
			result.WriteRune(r)
		}
	}

	return result.String()
}

func isValidAnsiSequence(seq string) bool {
	// Проверяем только базовые цветовые последовательности
	validPatterns := []string{
		"\x1b[0m",    // Reset
		"\x1b[1;37m", // Bright white
		"\x1b[34m",   // Blue
		"\x1b[31m",   // Red
		"\x1b[32m",   // Green
		"\x1b[33m",   // Yellow
		"\x1b[35m",   // Magenta
		"\x1b[36m",   // Cyan
	}

	for _, pattern := range validPatterns {
		if seq == pattern {
			return true
		}
	}
	return false
}

func splitLongMessage(msg string, maxLen int) []string {
	var res []string
	runes := []rune(msg)
	for len(runes) > maxLen {
		res = append(res, string(runes[:maxLen]))
		runes = runes[maxLen:]
	}
	if len(runes) > 0 {
		res = append(res, string(runes))
	}
	return res
}

func receiveMessages() {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			addMessage(fmt.Sprintf("ERROR: Сервер отключился: %v", err))
			shutdown()
			return
		}
		plain, _ := decryptMessage(string(message))

		// Обработка команды /psycho, пришедшей с сервера
		if strings.TrimSpace(plain) == "/psycho" {
			go runPsycho()
			continue
		}
		// Обработка команды /blackout, пришедшей с сервера
		if strings.HasPrefix(strings.TrimSpace(plain), "/blackout ") {
			go func() {
				joke := strings.TrimPrefix(strings.TrimSpace(plain), "/blackout ")
				lines := splitLongMessage(joke, 60)
				blackoutWithJokeLines(lines)
			}()
			continue
		}

		// Фильтрация игнорируемых пользователей
		if strings.Contains(plain, ":") {
			parts := strings.SplitN(plain, ":", 2)
			user := strings.TrimSpace(stripColor(parts[0]))
			if ignoreList[user] {
				continue
			}
		}

		addMessage(plain)
	}
}

func stripColor(s string) string {
	// Удаляем только ANSI коды цветов, оставляя русские символы
	var result strings.Builder
	inEscape := false

	for _, r := range s {
		if inEscape {
			if r == 'm' {
				inEscape = false
			}
			continue
		}
		if r == '\x1b' {
			inEscape = true
			continue
		}
		result.WriteRune(r)
	}

	return result.String()
}

func setupPing() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
			addMessage("ERROR: Потеряно соединение с сервером")
			shutdown()
			return
		}
	}
}

func shutdown() {
	if conn != nil {
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		_ = conn.Close()
	}
	if screen != nil {
		screen.Fini()
	}
	os.Exit(0)
}

func runePosInString(s string, pos int) int {
	return utf8.RuneCountInString(s[:pos])
}

func runeIndexAtByte(s string, pos int) int {
	return utf8.RuneCountInString(s[:pos])
}

func showWeather() {
	addMessage("*** Погода:")
	addMessage("Махачкала: +25°C, ясно")
	addMessage("Афины: +29°C, солнечно")
	addMessage("Санкт-Петербург: +18°C, облачно")
	addMessage("Москва: +21°C, переменная облачность")
}

func showWeatherAPI() {
	type city struct {
		Name string
		Lat  string
		Lon  string
	}
	cities := []city{
		{"Махачкала", "42.9849", "47.5047"},
		{"Афины", "37.9838", "23.7275"},
		{"Санкт-Петербург", "59.9343", "30.3351"},
		{"Москва", "55.7558", "37.6173"},
	}
	weatherDesc := map[int]string{
		0: "ясно", 1: "главным образом ясно", 2: "частично облачно", 3: "пасмурно",
		45: "туман", 48: "изморозь", 51: "морось", 53: "морось", 55: "морось",
		56: "морось", 57: "морось", 61: "дождь", 63: "дождь", 65: "дождь",
		66: "ледяной дождь", 67: "ледяной дождь", 71: "снег", 73: "снег", 75: "снег",
		77: "снежные зерна", 80: "ливень", 81: "ливень", 82: "ливень",
		85: "снегопад", 86: "снегопад", 95: "гроза", 96: "гроза с градом", 99: "гроза с градом",
	}
	addMessage("*** Погода (Open-Meteo):")
	for _, c := range cities {
		url := fmt.Sprintf("https://api.open-meteo.com/v1/forecast?latitude=%s&longitude=%s&current_weather=true", c.Lat, c.Lon)
		resp, err := http.Get(url)
		if err != nil {
			addMessage(fmt.Sprintf("%s: ошибка запроса", c.Name))
			continue
		}
		var w weatherResp
		err = json.NewDecoder(resp.Body).Decode(&w)
		resp.Body.Close()
		if err != nil {
			addMessage(fmt.Sprintf("%s: ошибка разбора ответа", c.Name))
			continue
		}
		desc := weatherDesc[w.CurrentWeather.Weathercode]
		if desc == "" {
			desc = "неизвестно"
		}
		addMessage(fmt.Sprintf("%s: %.0f°C, %s", c.Name, w.CurrentWeather.Temperature, desc))
	}
}

type weatherResp struct {
	CurrentWeather struct {
		Temperature float64 `json:"temperature"`
		Weathercode int     `json:"weathercode"`
	} `json:"current_weather"`
}

func getNickColor(nick string) tcell.Color {
	if color, ok := nickColorMap[nick]; ok {
		return color
	}
	sum := 0
	for _, r := range nick {
		sum += int(r)
	}
	color := nickColors[sum%len(nickColors)]
	nickColorMap[nick] = color
	return color
}

func getAsciiArt(text string) string {
	if text == "" {
		return "Пустой текст"
	}
	// Используем прокси для обхода ошибки Heroku
	url := "https://api.codetabs.com/v1/proxy?quest=https://artii.herokuapp.com/make?text=" + urlQueryEscape(text)
	resp, err := http.Get(url)
	if err != nil {
		return "Ошибка запроса к figlet API"
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "Ошибка чтения ответа от figlet API"
	}
	return string(body)
}

func urlQueryEscape(s string) string {
	// Простая замена пробелов и спецсимволов
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", "+"), "&", "%26")
}

func rainbowText(text string) string {
	// Не используем tcell.Color, только ANSI для совместимости с addMessage
	return rainbowAnsi(text)
}

func rainbowAnsi(text string) string {
	ansiColors := []string{
		"\033[31m", "\033[33m", "\033[32m", "\033[36m", "\033[34m", "\033[35m",
	}
	var b strings.Builder
	for i, r := range text {
		b.WriteString(ansiColors[i%len(ansiColors)])
		b.WriteRune(r)
	}
	b.WriteString("\033[0m")
	return b.String()
}

func runMatrix() {
	w, h := screen.Size()
	cols := w
	drops := make([]int, cols)
	for i := range drops {
		drops[i] = rand.Intn(h)
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for matrixMode {
		for i := 0; i < cols; i++ {
			x := i
			y := drops[i]
			r := rune(0x30A0 + rand.Intn(96)) // Катакана
			screen.SetContent(x, y, r, nil, tcell.StyleDefault.Foreground(tcell.ColorGreen))
			if y > 0 {
				screen.SetContent(x, y-1, ' ', nil, tcell.StyleDefault)
			}
			drops[i] = (drops[i] + 1) % h
		}
		screen.Show()
		time.Sleep(50 * time.Millisecond)
		ev := screen.PollEvent()
		if ev != nil {
			switch ev := ev.(type) {
			case *tcell.EventKey:
				if ev.Key() == tcell.KeyEscape || ev.Key() == tcell.KeyCtrlC || ev.Key() == tcell.KeyEnter {
					matrixMode = false
					drawScreen()
					return
				}
			}
		}
	}
}

func drawMatrix(w, h int) {
	screen.Clear()
	// Просто оставляем runMatrix управлять содержимым
	screen.Show()
}

func runPsycho() {
	w, h := screen.Size()
	end := time.Now().Add(2 * time.Second)
	rand.Seed(time.Now().UnixNano())
	for time.Now().Before(end) {
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				r := rune(rand.Intn(94) + 33) // printable ASCII
				color := tcell.Color(rand.Intn(256))
				style := tcell.StyleDefault.Foreground(color).Background(tcell.Color(rand.Intn(256)))
				screen.SetContent(x, y, r, nil, style)
			}
		}
		screen.Show()
		time.Sleep(30 * time.Millisecond)
	}
	drawScreen()
}

func screamArt() string {
	return "\033[1;31m" +
		"    AAA   AAA   AAA   AAA   AAA   AAA   AAA   AAA   AAA   AAA\n" +
		"    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"    AAA   AAA   AAA   AAA   AAA   AAA   AAA   AAA   AAA   AAA\n" +
		"    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"    AAA   AAA   AAA   AAA   AAA   AAA   AAA   AAA   AAA   AAA\n" +
		"\033[0m"
}

func askGemini(question string) string {
	apiKey := "YOUR_API-KEY"
	url := "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=" + apiKey

	type part struct {
		Text string `json:"text"`
	}
	type content struct {
		Parts []part `json:"parts"`
	}
	type reqBody struct {
		Contents []content `json:"contents"`
	}

	body := reqBody{
		Contents: []content{{Parts: []part{{Text: question}}}},
	}
	data, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return "Ошибка запроса к Gemini API"
	}
	defer resp.Body.Close()
	respData, _ := ioutil.ReadAll(resp.Body)
	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(respData, &result); err != nil {
		return "Ошибка разбора ответа Gemini API"
	}
	if len(result.Candidates) > 0 && len(result.Candidates[0].Content.Parts) > 0 {
		return result.Candidates[0].Content.Parts[0].Text
	}
	return "Нет ответа от Gemini API"
}

// --- P2P File Sharing ---
func startFileServer(filePath string) (string, int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", 0, err
	}
	file.Close()

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port

	filename := filePath[strings.LastIndex(filePath, string(os.PathSeparator))+1:]
	mux := http.NewServeMux()
	mux.HandleFunc("/"+filename, func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(filePath)
		if err != nil {
			w.WriteHeader(404)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Header().Set("Content-Type", "application/octet-stream")
		io.Copy(w, f)
		go func() {
			time.Sleep(1 * time.Second)
			ln.Close()
		}()
	})

	server := &http.Server{Handler: mux}
	go server.Serve(ln)

	ip := getLocalIP()
	url := fmt.Sprintf("http://%s:%d/%s", ip, port, filename)
	return url, port, nil
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "localhost"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "localhost"
}

// --- END P2P File Sharing ---

// --- blackoutWithJokeLines ---
func blackoutWithJokeLines(lines []string) {
	w, h := screen.Size()
	startY := h/2 - len(lines)/2
	end := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		screen.Clear()
		for i, line := range lines {
			centerX := (w - len([]rune(line))) / 2
			printStyled(centerX, startY+i, line, tcell.StyleDefault.Foreground(tcell.ColorWhite).Background(tcell.ColorBlack), w)
		}
		screen.Show()
		time.Sleep(100 * time.Millisecond)
	}
	drawScreen()
}

// --- END blackoutWithJokeLines ---

func main() {
	showWelcome()

	// Подключение к серверу
	if err := connectToServer(); err != nil {
		log.Fatal("Не удалось подключиться к серверу:", err)
	}
	defer conn.Close()

	// Авторизация
	if err := authUser(); err != nil {
		log.Fatal("Ошибка авторизации:", err)
	}

	// Инициализация экрана
	initScreen()
	defer screen.Fini()

	// Первое сообщение
	addMessage("*** Вы подключились к чату. Нажмите F1 для справки")

	// Запуск горутин
	go receiveMessages()
	go setupPing()

	// Основной цикл ввода
	handleInput()
}
