# WebSocket from Scratch (Go)

A WebSocket server implemented from scratch in Go, without any external libraries.

This is a study project — the goal is to understand how the WebSocket protocol works at a low level by implementing it manually on top of raw TCP.

## What it covers

- TCP server using `net.Listen`
- HTTP Upgrade handshake (RFC 6455)
- Frame parsing: reading FIN, opcode, mask, and payload length (3 cases: 7-bit, 16-bit, 64-bit)
- Frame writing: building binary frames to send back to clients
- XOR unmasking of client payloads
- Opcode handling: text, close, ping/pong
- Message fragmentation (FIN=0 continuation frames)
- Broadcast to multiple connected clients using a Hub with mutex protection

## Run

```bash
go run main.go
```

Then open a browser console and connect:

```javascript
const ws = new WebSocket("ws://localhost:8180")
ws.onmessage = (e) => console.log(e.data)
ws.onopen = () => ws.send("hello")
```

## Purpose

This project is purely for learning. The implementation intentionally avoids using Go's `net/http` or any WebSocket library so that every part of the protocol is written and understood by hand.
