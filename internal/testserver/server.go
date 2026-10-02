package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/websocket"
)

// Handler returns an intentionally vulnerable WebSocket handler for local testing.
func Handler() http.Handler {
	return http.HandlerFunc(serveWebSocket)
}

func serveWebSocket(writer http.ResponseWriter, request *http.Request) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	for {
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if !json.Valid(payload) {
			response := []byte(`{"error":"invalid JSON: unexpected input at /srv/wadjet/internal/testserver/server.go:29"}`)
			if err := conn.WriteMessage(websocket.TextMessage, response); err != nil {
				return
			}
			continue
		}
		if err := conn.WriteMessage(messageType, payload); err != nil {
			return
		}
	}
}
