# Reconify

Bug bounty recon tool with AI-powered analysis. Combines subdomain enumeration, JS recon, port scanning, content discovery, parameter mining, XSS scanning, and SSRF testing into a single pipeline with a live web dashboard and Telegram bot.

## Features

- **Subdomain enumeration** — crt.sh, HackerTarget, AlienVault OTX, Wayback Machine, DNS brute-force, subfinder
- **JS recon** — crawl JS files, extract endpoints and secrets (AWS keys, GitHub tokens, JWTs, Firebase, etc.)
- **Port scanning** — nmap / naabu wrapper with service fingerprinting
- **Content discovery** — Wayback Machine, CommonCrawl, URLScan, robots.txt, sitemap.xml, ffuf
- **Parameter mining** — Wayback URL mining, JS endpoint param extraction, GF-style XSS/SSRF/redirect classification
- **XSS scanning** — reflection testing, DOM sink analysis, CSP analysis, header reflection, blind XSS (interactsh), dalfox wrapper, WAF bypass mutations
- **SSRF scanning** — cloud metadata probing (AWS/GCP/Azure), IP obfuscation bypass, open redirect chaining, internal port scanning, host header injection
- **AI analysis** — Claude API synthesizes all findings into a prioritized attack surface report
- **Live web dashboard** — FastAPI + SSE with per-module progress cards, XSS/SSRF/Parameters tabs
- **Telegram bot** — receive live finding alerts and run scans from Telegram
- **CLI** — run scans, view reports, export JSON

---

## Quick Start (Linux Server)

### 1. System dependencies

```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git nmap
```

Optional tools (improve coverage if installed):
```bash
# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# naabu (fast port scanner)
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# ffuf (directory fuzzing)
go install github.com/ffuf/ffuf/v2@latest

# dalfox (XSS scanner)
go install github.com/hahwul/dalfox/v2@latest

# interactsh-client (blind XSS/SSRF callbacks)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

### 2. Clone the repo

```bash
git clone https://github.com/vijithvellora/reconify.git
cd reconify
```

### 3. Create a virtual environment and install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### 4. Set your API keys

**Anthropic API key** (optional — enables AI reports):
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

**Telegram bot** (optional — receive alerts and run scans via Telegram):
```bash
export TELEGRAM_TOKEN=1234567890:ABCdef...
export TELEGRAM_CHAT_ID=123456789
```
Get a token from [@BotFather](https://t.me/BotFather) on Telegram. Get your chat ID by messaging [@userinfobot](https://t.me/userinfobot).

Add permanently to your shell:
```bash
echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> ~/.bashrc
echo 'export TELEGRAM_TOKEN=...' >> ~/.bashrc
echo 'export TELEGRAM_CHAT_ID=...' >> ~/.bashrc
source ~/.bashrc
```

### 5. Start the web dashboard

```bash
reconify web --host 0.0.0.0 --port 8000
```

Then open `http://<your-server-ip>:8000` in your browser.

> **Note:** If you're behind a firewall, open port 8000:
> ```bash
> sudo ufw allow 8000
> ```

---

## Run as a background service (systemd)

To keep the server running after you close your SSH session:

### 1. Create the service file

```bash
sudo nano /etc/systemd/system/reconify.service
```

Paste the following (replace `yourusername` and the path as needed):

```ini
[Unit]
Description=Reconify Web Dashboard
After=network.target

[Service]
User=yourusername
WorkingDirectory=/home/yourusername/reconify
ExecStart=/home/yourusername/reconify/venv/bin/reconify web --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5
Environment=ANTHROPIC_API_KEY=sk-ant-...
Environment=TELEGRAM_TOKEN=...
Environment=TELEGRAM_CHAT_ID=...

[Install]
WantedBy=multi-user.target
```

### 2. Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable reconify
sudo systemctl start reconify
```

### 3. Check status / logs

```bash
sudo systemctl status reconify
sudo journalctl -u reconify -f
```

---

## CLI Usage

```bash
# Run full recon against a target (all modules)
reconify scan example.com

# Run specific modules only
reconify scan example.com --modules sub,js,params,xss,ssrf

# Skip AI analysis
reconify scan example.com --no-ai

# Control concurrency
reconify scan example.com --threads 30

# Output raw JSON
reconify scan example.com --output json

# List past scans
reconify list

# View AI report for a scan
reconify report 1

# Launch web dashboard
reconify web

# Start Telegram bot (polling — run in background or as systemd service)
reconify tgbot
```

### Available modules

| Module | Description |
|--------|-------------|
| `sub` | Subdomain enumeration (crt.sh, HackerTarget, OTX, Wayback, DNS brute-force) |
| `js` | JS file crawling + secret/endpoint extraction |
| `ports` | Port scanning with nmap/naabu |
| `content` | URL/directory discovery via Wayback, CommonCrawl, ffuf |
| `params` | Parameter mining from Wayback URLs + JS analysis with GF-style classification |
| `xss` | XSS reflection testing, DOM sinks, CSP analysis, blind XSS, dalfox |
| `ssrf` | Cloud metadata probing, internal port scan, open redirect chain, host header injection |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/scans` | List all scans |
| `POST` | `/api/scan` | Create a scan record |
| `POST` | `/api/scan/{id}/run` | Start all modules |
| `POST` | `/api/scan/{id}/module/{module}` | Run one module (sub/js/ports/content/params/xss/ssrf) |
| `GET` | `/api/scan/{id}/modules` | Per-module status + counts |
| `GET` | `/api/scan/{id}/module/{module}` | Findings for one module |
| `GET` | `/api/scan/{id}/events` | SSE live event stream |
| `GET` | `/api/scan/{id}/data` | All scan data |
| `GET` | `/api/scan/{id}/export` | Download JSON report |
| `DELETE` | `/api/scan/{id}` | Delete a scan |

---

## Configuration

Create `~/.reconify/config.yaml` to override defaults:

```yaml
threads: 30
timeout: 10
dns_wordlist: /path/to/custom/wordlist.txt
ffuf_wordlist: /usr/share/seclists/Discovery/Web-Content/common.txt
anthropic_api_key: sk-ant-...
web_host: 0.0.0.0
web_port: 8000

# Telegram bot
telegram_token: "1234567890:ABCdef..."
telegram_chat_id: "123456789"

# Blind XSS/SSRF callbacks via interactsh
# Leave empty to skip blind callback testing
interactsh_url: ""
# Example: interactsh_url: "https://YOUR_ID.interact.sh"
```

### Telegram bot commands

Start the bot with `reconify tgbot`, then in your Telegram chat:

| Command | Description |
|---------|-------------|
| `/scan example.com` | Start a full scan |
| `/scan example.com sub,js,xss` | Scan with specific modules |
| `/list` | List recent scans |
| `/status <id>` | Check scan status and module progress |
| `/report <id>` | Get the AI report for a scan |
| `/stop` | Stop the running scan |

The bot also sends proactive alerts for confirmed XSS/SSRF findings and secrets discovered in JS files.

---

## Data

Scan results are stored in `~/.reconify/reconify.db` (SQLite). Each scan persists results module-by-module as they complete.
