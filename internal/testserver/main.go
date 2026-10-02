package main

import (
	"log"
	"net/http"
)

func main() {
	server := &http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: Handler(),
	}
	log.Printf("vulnerable WebSocket test server listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
