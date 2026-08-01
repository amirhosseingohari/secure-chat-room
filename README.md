# Secure Chat Room

A multi-user secure chat room implemented in Python using TCP sockets, TLS/SSL, and SQLite.

## Features

- Secure TCP communication using TLS/SSL
- Multi-client chat room
- User authentication
- SQLite database for users and messages
- Recovery of missed messages after reconnecting
- Online users list
- Rate limiting to reduce message spam
- NDJSON protocol: one JSON message per line

## Project Structure
```text
secure-chat-room/
├── client/
│   └── client.py
├── server/
│   └── server.py
├── certs/
│   ├── server.crt        # Ignored by Git
│   └── server.key        # Ignored by Git
├── docs/
│   └── protocol.md
├── .gitignore
└── README.md
