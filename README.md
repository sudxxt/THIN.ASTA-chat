Here's the updated `README.md` file in English:

```markdown
# Think.Asta Chat

A secure chat application with end-to-end encryption, rooms, and fun features (Gemini API, ASCII art, etc.).

## 🚀 Installation

1. Ensure you have Go (version 1.20+) installed:
   ```bash
   go version
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/your_username/think-asta-chat.git
   cd think-asta-chat
   ```

3. Install dependencies:
   ```bash
   go mod download
   ```

## 🔥 Running

### Server
```bash
go run main.go
```
Select mode (local/remote). Server will run at `http://localhost:8080`.

### Client
```bash
go run client/main.go
```
On first run:
1. Enter server address
2. Provide username, password, and room

## 🌐 Remote Connection via ngrok

1. First launch the server in remote mode (option 2 when starting)

2. Install ngrok (if you haven't):
   ```bash
   choco install ngrok (Windows)
   brew install ngrok (Mac)
   sudo snap install ngrok (Linux)
   ```

3. Start ngrok tunnel:
   ```bash
   ngrok http 8080
   ```

4. You'll see output like:
   ```
   Forwarding https://abc123.ngrok.io -> http://localhost:8080
   ```

5. In the client:
   - Choose option "2" (Remote server)
   - Enter the ngrok URL with /ws suffix:
     ```
     wss://abc123.ngrok.io/ws
     ```

6. Share the ngrok URL with friends to connect to your server!

## 🔑 Gemini API Setup

For `/geymini` command:
1. Get API key from [Google AI Studio](https://aistudio.google.com/)
2. Replace `YOUR_API-KEY` in `client/main.go` (~line 650):
   ```go
   apiKey := "YOUR_KEY_HERE"
   ```

## 🎮 Chat Commands

### Basic
| Command          | Description                      |
|------------------|----------------------------------|
| `/nick <name>`   | Change nickname                  |
| `/msg <user> <text>` | Private message              |
| `/create <room>` | Create new room                  |
| `/ignore <user>` | Ignore a user                    |

### Fun
| Command          | Description                      |
|------------------|----------------------------------|
| `/ascii <text>`  | Generate ASCII art               |
| `/rainbow <text>`| Rainbow-colored text             |
| `/psycho`        | Psychedelic animation            |
| `/blackout`      | Dark room with Gemini joke       |

### Developer
| Command          | Description                      |
|------------------|----------------------------------|
| `/sendfile <path>` | Send file (P2P)               |
| `/matrix`        | Matrix animation (Exit: Esc)     |

Full list: type `/help` in chat.

## 🔒 Security

All messages are encrypted with AES-256 using SHA-256 hash of user's password.
```

Key changes made:
1. Removed the License section completely
2. Added detailed ngrok connection instructions including:
   - Installation commands for all platforms
   - Step-by-step connection guide
   - Example of ngrok URL format
   - Instructions for sharing the server
3. Kept all other sections intact
4. Maintained consistent markdown formatting
