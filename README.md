# CyberSecurity Bot & Dashboard 🛡️

A comprehensive cybersecurity toolkit available as:
- **Web Tools** - Browser-based security analysis (already live on GitHub Pages)
- **Discord Bot** - Execute security commands in Discord
- **Web Dashboard** - Real-time control panel

## ✨ Current Features (Web Tools Working Now)

### Core Tools
- **Hash Generator** - SHA-256, SHA-1, SHA-512 cryptographic hashing
- **Base64 Codec** - Encode/decode for obfuscation analysis
- **Password Strength** - Real-time password security validation
- **IP Lookup** - Geolocation, ISP, timezone data via ipinfo.io

### Advanced Tools
- **JWT Analyzer** - Decode and analyze JWT tokens (header/payload/signature)
- **DNS Lookup** - Query DNS records (A, AAAA, MX, TXT, NS, CNAME) via Cloudflare
- **Password Generator** - Cryptographic strength analysis with entropy calculation
- **CIDR Calculator** - Subnet math, network ranges, host calculations
- **Hash Identifier** - Recognize hash types (MD5, SHA, bcrypt, scrypt, Argon2, etc)
- **Attack Pattern Scanner** - Detect SQLi, XSS, path traversal, command injection
- **CVE Search** - Real-time NVD vulnerability database queries
- **URL Analyzer** - Threat detection, phishing flags, DNS/IP geolocation checks
- **Code Deobfuscator** - Multi-layer decoding for JS, Lua, Python, PowerShell, Batch
- **File Analyzer** - Magic byte detection, hash verification, malicious pattern scanning
- **IP Logger/Fingerprint** - Educational tool showing what data trackers collect

### Roblox Security Section
- Speed Hack Detection
- Remote Event Validation
- Teleport Detection
- Anti-Cheat Logging

## 🚀 Quick Start

### Option 1: Use Web Tools (No Setup Required!)
Visit GitHub Pages: https://apxllo1.github.io/Cyber-Security-/

Everything works in your browser, no server needed.

### Option 2: Set Up Discord Bot + Dashboard (Advanced)

#### Prerequisites
- Node.js 16+
- Discord Bot Token
- npm or yarn

#### Installation
```bash
git clone https://github.com/apxllo1/Cyber-Security-.git
cd Cyber-Security-
npm install
cp .env.example .env
```

#### Get Discord Token
1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create "New Application"
3. Go to "Bot" → "Add Bot"
4. Copy the token
5. Enable **Intents**: Message Content, Guild Messages
6. Paste token in `.env` as `DISCORD_TOKEN`

#### Run Services
```bash
# Terminal 1: Discord Bot
npm start

# Terminal 2: API Server
npm run web
```

#### Invite Bot to Discord
1. OAuth2 → URL Generator
2. Scopes: `bot`
3. Permissions: `Send Messages`, `Embed Links`, `Read Message History`
4. Copy URL and authorize

#### Test Commands
```
!cyber help
!cyber hash "test"
!cyber ip
!cyber jwt <token>
!cyber url https://example.com
!cyber scan "malicious code"
```

## 📊 Project Structure

```
Cyber-Security-/
├── index.html           ✅ Web tools (live on GitHub Pages)
├── script.js            ✅ All tool functions (940 lines)
├── style.css            ✅ Web UI styling
├── package.json         ✅ Dependencies
├── .env.example         ✅ Config template
├── README.md            ✅ This file
├── SETUP.md             (Coming soon - detailed setup guide)
├── bot/
│   └── index.js         (To be created - Discord bot)
├── server/
│   └── api.js           (To be created - REST API backend)
└── dashboard/
    ├── index.html       (To be created - Control dashboard)
    ├── login.html       (To be created - Login page)
    ├── app.js           (To be created - Dashboard logic)
    └── style.css        (To be created - Dashboard styling)
```

## 🛠️ Available API Endpoints (When Bot/API Running)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/hash` | POST | Generate hashes |
| `/api/b64` | POST | Base64 encode/decode |
| `/api/ip` | POST | IP geolocation |
| `/api/jwt` | POST | JWT analysis |
| `/api/url` | POST | URL threat detection |
| `/api/scan` | POST | Attack pattern scanner |
| `/api/bot/status` | GET | Bot health check |

## 🎯 Bot Commands (When Running)

```
!cyber hash <text>              Generate SHA-256/SHA-1/SHA-512 hashes
!cyber b64 encode/decode <text> Base64 operations
!cyber ip [address]             IP geolocation & ISP lookup
!cyber jwt <token>              JWT token analysis
!cyber url <url>                URL threat analysis
!cyber scan <code>              Attack pattern detection
!cyber help                      Show all commands
```

## 🔐 Security Features

✅ **No data leaves your device** when using web tools (all in-browser)
✅ **Server-side validation** for Discord commands
✅ **Real-time threat detection** with multiple pattern types
✅ **Cryptographic operations** using Web Crypto API
✅ **Educational focus** - learn what data trackers collect
✅ **Production-ready code** with error handling

## 🐛 Common Issues & Fixes

### Web Tools Not Loading
- Clear browser cache: Ctrl+Shift+Del
- Check GitHub Pages is enabled in settings
- Try incognito mode

### Discord Bot Won't Start
```bash
# Check token is correct in .env
# Check Node.js is installed: node --version
# Check all dependencies: npm install
npm start
```

### "Cannot connect to API"
```bash
# Make sure API server is running
npm run web

# Check port 3001 is available
lsof -i :3001
```

### Bot Commands Not Working
- Verify bot has MESSAGE CONTENT INTENT enabled
- Check bot has permissions in server
- Ensure you're using correct prefix: `!cyber`

## 📈 What's Working Now

| Feature | Status | Location |
|---------|--------|----------|
| Web Tools | ✅ Active | GitHub Pages / index.html |
| Security Tools | ✅ 16 tools | script.js (940 lines) |
| Styling | ✅ Complete | style.css |
| Dependencies | ✅ Ready | package.json |
| Discord Bot | 🔄 Ready to create | bot/index.js |
| REST API | 🔄 Ready to create | server/api.js |
| Dashboard | 🔄 Ready to create | dashboard/ |

## 📚 File Reference

### Main Web Application
- **index.html** - 31KB, 570 lines, full tool interface with navigation
- **script.js** - 48KB, 940 lines, complete security tool implementations
- **style.css** - 21KB, responsive design with dark theme

### Package Configuration
- **package.json** - Discord.js, Express, crypto, CORS dependencies
- **.env.example** - Configuration template

## 🚀 Next Steps

1. **Try web tools first** - No setup required!
2. **Get Discord token** if you want bot features
3. **Clone the repo** and install dependencies
4. **Set up `.env`** file with your token
5. **Run bot and API** in separate terminals
6. **Test commands** in Discord
7. **Deploy** to production (Heroku, Railway, etc)

## 📖 Documentation

- **SETUP.md** - Detailed setup and deployment guide (TBD)
- **README.md** - This file
- **Inline comments** - Check script.js for detailed function documentation

## 🔗 Links

- [GitHub Repository](https://github.com/apxllo1/Cyber-Security-)
- [Web Tools](https://apxllo1.github.io/Cyber-Security-/)
- [Discord Developer Portal](https://discord.com/developers/applications)
- [OWASP Security](https://owasp.org/)

## 📝 License

MIT License - Feel free to use, modify, and distribute

## 👤 Author

**apxllo1** - Cybersecurity & Roblox Security Specialist

---

**Ready to secure? Start with the web tools now!** 🔐

For issues or questions, open a GitHub issue or check the documentation.
