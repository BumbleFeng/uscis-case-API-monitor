# USCIS Case API Monitor

> **Disclaimer**: This project is for educational and personal use only. Automated access to USCIS/login.gov may violate their Terms of Service. The authors are not responsible for any consequences arising from the use of this tool. Use at your own risk.

Automated USCIS case status monitor that checks your immigration cases periodically via the USCIS API and notifies you via Discord when something changes. Currently supports IOE receipt numbers.

## Features

- **Multi-case monitoring** — track multiple receipt numbers simultaneously
- **Automatic login** — Playwright + Chrome handles myUSCIS login automatically
- **SMS/iMessage OTP** — reads verification codes from macOS Messages database (no email delays)
- **Smart session management** — reuses saved auth tokens; auto-re-authenticates when expired
- **Change detection** — SHA-based field-level diff on `updatedAt`, `events`, `closed`, `actionRequired`
- **Discord notifications** — sends alerts on case changes (or a quiet heartbeat when nothing changed)
- **Built-in scheduler** — runs on weekdays 9 AM–8 PM ET, every 3 hours

## Requirements

- macOS (for iMessage/SMS OTP reading)
- Node.js 20+
- Python 3.10+
- Google Chrome installed
- Full Disk Access granted to Terminal/VS Code (System Settings → Privacy & Security → Full Disk Access)

## Install

```bash
npm install
npx playwright install chromium
```

## Configure

Copy the example config and fill in your details:

```bash
cp config.example.json config.local.json
```

Edit `config.local.json`:

```json
{
  "uscisEmail": "you@example.com",
  "uscisUsername": "you@example.com",
  "uscisPassword": "your-password",
  "receiptNumbers": [
    "IOE0934xxxxxx",
    "IOE0934xxxxxx"
  ],
  "loginUrl": "https://my.uscis.gov/oidc/login",
  "monitorUrl": "https://myaccount.uscis.gov/",
  "apiUrl": "https://my.uscis.gov/account/case-service/api/cases",
  "discordWebhookUrl": "https://discord.com/api/webhooks/...",
  "otp": {
    "mode": "sms-imessage",
    "timeoutSeconds": 300,
    "pollIntervalSeconds": 2,
    "sinceSeconds": 1200,
    "codeRegex": "\\b(\\d{6})\\b"
  }
}
```

### OTP Modes

**SMS/iMessage** (recommended for macOS):
```json
"otp": {
  "mode": "sms-imessage",
  "timeoutSeconds": 300,
  "pollIntervalSeconds": 2,
  "sinceSeconds": 1200,
  "codeRegex": "\\b(\\d{6})\\b"
}
```
Reads OTP codes directly from the macOS Messages database. Requires Full Disk Access permission.

**IMAP Email**:
```json
"otp": {
  "mode": "imap",
  "timeoutSeconds": 180,
  "pollIntervalSeconds": 5,
  "sinceSeconds": 900,
  "imapHost": "imap.mail.me.com",
  "imapPort": 993,
  "imapUsername": "you@icloud.com",
  "imapPassword": "your-app-specific-password",
  "imapMailbox": "INBOX",
  "imapUseSsl": true,
  "senderContains": "uscis",
  "subjectContains": "verification",
  "codeRegex": "\\b(\\d{6})\\b"
}
```

### Discord Notifications

Set `discordWebhookUrl` in config, or use the environment variable:

```bash
export PHONEMONITOR_DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
```

- **No changes**: sends a simple timestamp + "no changes found"
- **Changes detected**: sends a rich embed with receipt number, changed fields, and new events

## Commands

All management is done through `./uscis.sh`:

| Command | Description |
|---------|-------------|
| `./uscis.sh start` | Start scheduler as a background daemon |
| `./uscis.sh stop` | Stop the scheduler |
| `./uscis.sh status` | Check if scheduler is running (PID + uptime) |
| `./uscis.sh restart` | Restart the scheduler |
| `./uscis.sh logs [N]` | Show last N lines of log (default 50) |
| `./uscis.sh follow` | Tail log in real time (`Ctrl+C` to stop) |

Additional npm scripts for development/debugging:

| Command | Description |
|---------|-------------|
| `npm run login` | Log in to myUSCIS and save session |
| `npm run check-all-cases` | Check all cases using saved session |
| `npm run scheduled-check` | Run a single check (auto-login if needed) |

## Usage

### First-time setup

```bash
# 1. Install dependencies
npm install

# 2. Create and edit config
cp config.example.json config.local.json

# 3. Login (opens browser, handles OTP automatically)
npm run login

# 4. Verify it works
npm run check-all-cases
```

### Start the scheduler

```bash
./uscis.sh start
```

This starts the scheduler as a background daemon — safe to close the terminal.

- PID saved to `state/scheduler.pid`
- Logs written to `state/scheduler.log`
- Schedule: weekdays 9 AM–8 PM ET, every 3 hours

The scheduler automatically:
1. Checks if current time is within schedule
2. Fetches case data via the USCIS API
3. Re-authenticates if the session expired (browser + SMS OTP)
4. Compares results against history and sends Discord notifications
5. Sleeps until the next scheduled run

### Monitor & manage

```bash
# Is it running?
./uscis.sh status
# ✅ Scheduler is running (PID 12345, uptime 2:30:00)

# Check recent activity
./uscis.sh logs

# Watch live
./uscis.sh follow

# Restart after config change
./uscis.sh restart

# Stop
./uscis.sh stop
```

### Run a one-off check

```bash
npm run scheduled-check
```

Same logic as the scheduler, but runs once and exits.

## How It Works

```
scheduled-check
  ├── Has auth token? ──No──→ login (browser + OTP)
  │         │
  │        Yes
  │         ↓
  ├── Fetch cases via API
  │         │
  │    Token expired?
  │     ├── Yes → auto-login → retry
  │     └── No  → compare with history
  │                  │
  │           Changes found?
  │            ├── Yes → Discord embed with details
  │            └── No  → Discord: "no changes found"
  │
  └── Save history to state/case-history.json
```

## Data Files

| File | Description |
|------|-------------|
| `state/auth.json` | Saved browser session (cookies) |
| `state/case-history.json` | Full case history with change tracking |
| `config.local.json` | Your configuration (gitignored) |

## Built With Vibe Coding

This entire project was built through vibe coding with AI (GitHub Copilot / Claude). From the initial Playwright automation to SMS OTP reading, Discord notifications, scheduler, and daemon management — every line of code was generated, debugged, and iterated through natural language conversation. No code was written manually.

## License

MIT — see [LICENSE](LICENSE) for details.
