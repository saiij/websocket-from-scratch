package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

const GUIDRFC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type OpCode byte

var (
	OpCodeText   OpCode = 0x1
	OpCodeBinary OpCode = 0x2
	OpCodeClose  OpCode = 0x8
	OpCodePing   OpCode = 0x9
	OpCodePong   OpCode = 0xA
)

type Hub struct {
	clients map[net.Conn]bool
	mu      sync.RWMutex
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[net.Conn]bool),
	}
}

func main() {
	listener, err := net.Listen("tcp", ":8180")
	if err != nil {
		panic(err)
	}

	defer listener.Close()

	hub := NewHub()

	for {
		conn, err := listener.Accept() // bloquea hasta que alguien se conecta
		// cada conn es una conexion independiente
		// go lanza una goroutine
		if err != nil {
			panic(err)
		}
		go hub.handleConn(conn)

	}
}

func (h *Hub) handleConn(conn net.Conn) {
	h.mu.Lock()
	h.clients[conn] = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, conn)
		h.mu.Unlock()
	}()
	defer conn.Close()

	// leer header
	b := make([]byte, 1024)
	n, _ := conn.Read(b)
	headerStr := string(b[:n])
	parts := strings.Split(headerStr, "\r\n")
	fmt.Println(len(parts)) // me he dadod cuanta que es 15
	fmt.Println(parts)
	headerMap := make(map[string]string)
	for _, line := range parts {
		val := strings.SplitN(line, ": ", 2)
		fmt.Println(val)
		if len(val) < 2 {
			continue
		}
		headerMap[val[0]] = val[1]
	}

	fmt.Println(headerMap)

	secWS := headerMap["Sec-WebSocket-Key"]
	fmt.Println("Sec-WebSocket-Key => ", secWS)

	raw := secWS + GUIDRFC

	hash := sha1.New()
	hash.Write([]byte(raw))
	hashed := hash.Sum(nil)

	accept := base64.StdEncoding.EncodeToString(hashed)
	conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n"))
	conn.Write([]byte("Upgrade: websocket\r\n"))
	conn.Write([]byte("Connection: Upgrade\r\n"))
	conn.Write([]byte(fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", accept)))
	conn.Write([]byte("\r\n"))

	// despues del handskacke el navegador ya no envia texto, envia frame binarios
	// frame es la estructura que usa websocket para saber donde termina cada mensaje, cada frame tiene un header donde indica eso

	var fragBuffer []byte
	var fragOpCode OpCode

	for { // se usa un loop para tener una conexion persistente con el cliente , de esta forma puede enviar mas de 1 message sin que la conexion se cierre
		header := make([]byte, 2)
		_, err := io.ReadFull(conn, header)
		if err != nil {
			return
		}

		fin := header[0] & 0x80    // apaga todo menos el byte 7
		opcode := header[0] & 0x0F // apaga todo menos el byte 3-0

		var opCodeType OpCode

		switch opcode {
		case 0x1:
			opCodeType = OpCodeText
		case 0x2:
			opCodeType = OpCodeBinary
		case 0x8:
			opCodeType = OpCodeClose
		case 0x9:
			opCodeType = OpCodePing
		case 0xA:
			opCodeType = OpCodePong
		}
		masked := header[1] & 0x80
		payloadLen := header[1] & 0x7F

		if masked == 0 {
			return
		}

		if payloadLen <= 125 {
			// ya es el largo real
			length := payloadLen

			maskingKey := make([]byte, 4)
			if _, err := io.ReadFull(conn, maskingKey); err != nil {
				return
			}

			payloadBuff := make([]byte, length)
			if _, err := io.ReadFull(conn, payloadBuff); err != nil {
				return
			}

			for i := range payloadBuff {
				payloadBuff[i] = payloadBuff[i] ^ maskingKey[i%4]
			}

			if fin == 0 { // es un fragmento , no esta completo el message
				// frame intermedio , acomular y continuar
				fragBuffer = append(fragBuffer, payloadBuff...)
				if opCodeType != 0x0 {
					fragOpCode = opCodeType // cuardar opCode del ptimer frame
				}
				continue
			} else {
				// el ultimo o unico frame
				fragBuffer = append(fragBuffer, payloadBuff...)
				// si fragOpCode tiene algo es un msg fragmentado
				// si no es un mensaje de un solo frame
			}

			fmt.Printf("opcode: %d, mensaje: %s\n", opcode, string(payloadBuff))

			finalOpCode := opCodeType
			if fragOpCode != 0 {
				finalOpCode = fragOpCode
			}

			switch finalOpCode {
			case OpCodeText:
				h.Broadcast(fragBuffer)
			case OpCodeClose:
				conn.Write([]byte{0x88, 0x00})
				return
			case OpCodePing:
				pong := make([]byte, 2+len(fragBuffer))
				pong[0] = 0x8A
				pong[1] = byte(len(fragBuffer))
				copy(pong[2:], fragBuffer)
				conn.Write(pong)
			}

			fragBuffer = nil
			fragOpCode = 0

		}

		if payloadLen == 126 {
			// esta en los proxumo 2 bytes
			extLength := make([]byte, 2)

			if _, err := io.ReadFull(conn, extLength); err != nil {
				return
			}

			// el <<8 desplaza el primer byte 8 posiciones a la izquierda (lo pone en la parte alta) y el | lo combina  con el segundo byte.
			length := uint16(extLength[0])<<8 | uint16(extLength[1])

			maskingKey := make([]byte, 4)
			if _, err := io.ReadFull(conn, maskingKey); err != nil {
				return
			}

			payloadBuff := make([]byte, length)
			if _, err := io.ReadFull(conn, payloadBuff); err != nil {
				return
			}

			for i := range payloadBuff {
				payloadBuff[i] = payloadBuff[i] ^ maskingKey[i%4]
			}

			if fin == 0 { // es un fragmento , no esta completo el message
				// frame intermedio , acomular y continuar
				fragBuffer = append(fragBuffer, payloadBuff...)
				if opCodeType != 0x0 {
					fragOpCode = opCodeType // cuardar opCode del ptimer frame
				}
				continue
			} else {
				// el ultimo o unico frame
				fragBuffer = append(fragBuffer, payloadBuff...)
				// si fragOpCode tiene algo es un msg fragmentado
				// si no es un mensaje de un solo frame
			}

			fmt.Printf("opcode: %d, mensaje: %s\n", opcode, string(payloadBuff))

			finalOpCode := opCodeType
			if fragOpCode != 0 {
				finalOpCode = fragOpCode
			}

			switch finalOpCode {
			case OpCodeText:
				h.Broadcast(fragBuffer)
			case OpCodeClose:
				conn.Write([]byte{0x88, 0x00})
				return
			case OpCodePing:
				pong := make([]byte, 2+len(fragBuffer))
				pong[0] = 0x8A
				pong[1] = byte(len(fragBuffer))
				copy(pong[2:], fragBuffer)
				conn.Write(pong)
			}

			fragBuffer = nil
			fragOpCode = 0

		}

		if payloadLen == 127 {
			// el largo esta en los proximo 8 bytes
			extLength := make([]byte, 8)

			if _, err := io.ReadFull(conn, extLength); err != nil {
				return
			}

			length := uint64(extLength[0])<<56 | uint64(extLength[1])<<48 | uint64(extLength[2])<<40 | uint64(extLength[3])<<32 |
				uint64(extLength[4])<<24 | uint64(extLength[5])<<16 | uint64(extLength[6])<<8 | uint64(extLength[7])

			maskingKey := make([]byte, 4)
			if _, err := io.ReadFull(conn, maskingKey); err != nil {
				return
			}

			payloadBuff := make([]byte, length)
			if _, err := io.ReadFull(conn, payloadBuff); err != nil {
				return
			}

			for i := range payloadBuff {
				payloadBuff[i] = payloadBuff[i] ^ maskingKey[i%4]
			}

			if fin == 0 { // es un fragmento , no esta completo el message
				// frame intermedio , acomular y continuar
				fragBuffer = append(fragBuffer, payloadBuff...)
				if opCodeType != 0x0 {
					fragOpCode = opCodeType // cuardar opCode del ptimer frame
				}
				continue
			} else {
				// el ultimo o unico frame
				fragBuffer = append(fragBuffer, payloadBuff...)
				// si fragOpCode tiene algo es un msg fragmentado
				// si no es un mensaje de un solo frame
			}

			fmt.Printf("opcode: %d, mensaje: %s\n", opcode, string(payloadBuff))

			finalOpCode := opCodeType
			if fragOpCode != 0 {
				finalOpCode = fragOpCode
			}

			switch finalOpCode {
			case OpCodeText:
				h.Broadcast(fragBuffer)
			case OpCodeClose:
				conn.Write([]byte{0x88, 0x00})
				return
			case OpCodePing:
				pong := make([]byte, 2+len(fragBuffer))
				pong[0] = 0x8A
				pong[1] = byte(len(fragBuffer))
				copy(pong[2:], fragBuffer)
				conn.Write(pong)
			}

			fragBuffer = nil
			fragOpCode = 0

		}

	}
}

func WriteMessage(conn net.Conn, msg []byte) {
	//  Byte 0: FIN=1 + opcode
	//  Byte 1: longitud del payload (sin bit de mask)
	//  Payload: los bytes del mensaje

	if len(msg) <= 125 {
		responseBuffer := make([]byte, 2+len(msg))
		responseBuffer[0] = 0x81
		responseBuffer[1] = byte(len(msg))
		copy(responseBuffer[2:], msg)

		if _, err := conn.Write(responseBuffer); err != nil {
			fmt.Println("error writing response")
			return
		}

	} else if len(msg) <= 65535 { // == 126

		length := len(msg)
		responseBuffer := make([]byte, 2+2+length)
		responseBuffer[0] = 0x81
		responseBuffer[1] = 126
		responseBuffer[2] = byte(length >> 8) // parte alta
		responseBuffer[3] = byte(length)
		copy(responseBuffer[4:], msg)

		if _, err := conn.Write(responseBuffer); err != nil {
			fmt.Println("error writing response")
			return
		}

	} else { // == 127
		length := len(msg)
		responseBuffer := make([]byte, 2+8+length)
		responseBuffer[0] = 0x81
		responseBuffer[1] = 127
		responseBuffer[2] = byte(length >> 56)
		responseBuffer[3] = byte(length >> 48)
		responseBuffer[4] = byte(length >> 40)
		responseBuffer[5] = byte(length >> 32)
		responseBuffer[6] = byte(length >> 24)
		responseBuffer[7] = byte(length >> 16)
		responseBuffer[8] = byte(length >> 8) // parte baja
		responseBuffer[9] = byte(length)
		copy(responseBuffer[10:], msg)

		if _, err := conn.Write(responseBuffer); err != nil {
			fmt.Println("error writing response")
			return
		}

	}
}

func (h *Hub) Broadcast(msg []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for conn := range h.clients {
		WriteMessage(conn, msg)
	}
}
