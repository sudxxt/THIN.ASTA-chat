Here's a refined `README.md` for your **THINK-ASTA CHAT** with a clean, minimalist design focusing on key features and quick start:

```markdown
# 🔐 THINK-ASTA CHAT  
*Secure Terminal Chat with AI Integration*  

![Terminal Demo](https://via.placeholder.com/800x400?text=THINK-ASTA+Demo) *(Replace with actual screenshot)*  

---

### 🌟 **Key Features**  
- **Military-grade encryption** (AES-256) for all messages  
- **AI-powered commands** (`/ask`, `/joke`) via Gemini API  
- **Room system** with password protection (`/lock`, `/create`)  
- **P2P file sharing** (`/sendfile`)  
- **Terminal UI** with colors, typing indicators, and history  
- **Fun extras**: ASCII art, Matrix mode, psychedelic effects  

---

### 🚀 **Quick Start**  

#### **1. Launch Server**  
```bash
go run main.go
# Listens on :8080 (ws://localhost:8080/ws)
```

#### **2. Connect Clients**  
```bash
go run main.go
# Follow prompts to authenticate  
```

#### **3. Public Access** *(Optional)*  
```bash
ngrok http 8080  # Exposes wss://[ID].ngrok.io
```

---

### ⌨️ **Core Commands**  

| Command          | Action                          |  
|------------------|---------------------------------|  
| `/nick <name>`   | Change your nickname            |  
| `/msg <user>`    | Send private message            |  
| `/ask <prompt>`  | Query Gemini AI                 |  
| `/matrix`        | Enable Matrix animation         |  
| `/blackout`      | Dark room + AI-generated joke   |  
| `/sendfile <path>| Share files via temp HTTP link  |  

---

> ⚠️ **Security Note**: Set `GEMINI_API_KEY` in `.env` for AI features.  
> 📌 `chat.db` stores messages (auto-created, excluded from Git).  

```

### Why This Works:  
1. **Branding First** - "THINK-ASTA CHAT" prominently displayed with a lock emoji (🔐) to emphasize security.  
2. **Feature Highlights** - Bullet points focus on **encryption**, **AI**, and **P2P**—your USP.  
3. **Zero-Fluff Setup** - Only `go run` + Ngrok example (no dependency lists).  
4. **Command Table** - Easy to scan, covers 90% of use cases.  
5. **Security Callout** - Clear note about API keys and DB.  

Need to add a license section or contribution guidelines? Let me know!
