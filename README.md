# Vague Bot

Unofficial bot for **Vague Chat** - the Android chat application.

> For entertainment purposes: fun bot, selfbot, war bot, and other automated features.

## Features

- **Multi-Account Support** - Run multiple bot instances simultaneously
- **End-to-End Encryption (E2EE)** - Secure communication with the Vague platform
- **Real-time Chat Stream** - Listen and respond to messages in real-time
- **Selfbot Functions** - Custom automated responses and actions
- **War Bot** - Battle system with other bots
- **gRPC Backend** - Fast and efficient communication protocol

## Requirements

- Go 1.22+
- Git

## Installation

```bash
# Clone the repository
git clone https://github.com/fckveza/vague-bot.git
cd vague-bot

# Download dependencies
go mod download
```

## Configuration

Create an `account.json` file in the project root:

```json
{
  "accounts": [
    {
      "cid": "your_cid",
      "email": "your_email@example.com",
      "passwd": "your_password",
      "token": "",
      "refresh_token": "",
      "revision": 0,
      "device_id": "your_device_id",
      "e2ee_public_key": "your_public_key",
      "e2ee_private_key": "your_private_key"
    }
  ]
}
```

Edit `config.json` to customize bot settings:

```json
{
  "account_file": "account.json",
  "target": "your_target_server",
  "auth_server": "auth_server_address",
  "message_server": "message_server_address"
}
```

## Usage

```bash
# Run the bot
go run main.go
```

The bot will:
1. Load accounts from `account.json`
2. Initialize E2EE keys
3. Accept pending invitations
4. Start listening to chat streams
5. Run all bot clients concurrently

Press `Ctrl+C` to gracefully shutdown.

## Project Structure

```
vague-bot/
├── main.go              # Entry point
├── config.json          # Bot configuration
├── account.json         # Account credentials
├── go.mod               # Go module definition
├── proto/               # Protocol Buffer definitions
│   ├── bot.pb.go
│   └── bot_grpc.pb.go
└── vaguebot/            # Core bot implementation
    ├── client.go        # Bot client
    ├── chatstream.go    # Chat stream handler
    ├── config.go        # Configuration loader
    ├── e2ee.go          # E2EE implementation
    ├── events.go        # Event handlers
    ├── store.go         # Account store
    └── util.go          # Utilities
```

## Technical Details

- **Protocol**: gRPC for efficient client-server communication
- **Encryption**: End-to-end encryption using X25519 + AES-GCM
- **Authentication**: Token refresh mechanism with automatic re-authentication
- **Reconnection**: Automatic reconnection with exponential backoff

---

## Get Free Tokens

**Free 10 tokens for new users!** 🎁

Register and chat account here: https://link.vague-infinity.com/users/ax2

---

## Disclaimer

This is an **unofficial** bot for the Vague Chat application. Use at your own risk. The developers are not responsible for any account bans or other consequences from using this bot.

## License

MIT License

---

**Made for Vague Chat enthusiasts** 🎮
