package checks

import (
	"context"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCheckRateLimit(t *testing.T) {
	var received atomic.Int32
	server, target := echoWebSocketServer(t, func(_ http.ResponseWriter, _ *http.Request) {})
	defer server.Close()
	server.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				return
			}
			received.Add(1)
			if err := conn.WriteMessage(messageType, message); err != nil {
				return
			}
		}
	})

	finding, err := CheckRateLimit(context.Background(), target, testConnectionOptions(), 3)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v", err)
	}
	if finding == nil || finding.ID != "rate-limit" {
		t.Fatalf("CheckRateLimit() = %#v, want rate-limit finding", finding)
	}
	if got := received.Load(); got != 3 {
		t.Fatalf("server received %d messages, want 3", got)
	}
}

func TestCheckRateLimitCapsBurst(t *testing.T) {
	var received atomic.Int32
	server, target := echoWebSocketServer(t, nil)
	defer server.Close()
	server.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				return
			}
			received.Add(1)
			if err := conn.WriteMessage(messageType, message); err != nil {
				return
			}
		}
	})

	_, err := CheckRateLimit(context.Background(), target, testConnectionOptions(), DefaultRateLimitCount+10)
	if err != nil {
		t.Fatalf("CheckRateLimit() error = %v", err)
	}
	if got := received.Load(); got != DefaultRateLimitCount {
		t.Fatalf("server received %d messages, want capped count %d", got, DefaultRateLimitCount)
	}
}

func TestCheckMessageSize(t *testing.T) {
	server, target := echoWebSocketServer(t, nil)
	defer server.Close()
	finding, err := CheckMessageSize(context.Background(), target, testConnectionOptions())
	if err != nil {
		t.Fatalf("CheckMessageSize() error = %v", err)
	}
	if finding == nil || finding.ID != "message-size" {
		t.Fatalf("CheckMessageSize() = %#v, want message-size finding", finding)
	}
}

func TestCheckVerboseErrors(t *testing.T) {
	server, target := echoWebSocketServer(t, func(writer http.ResponseWriter, request *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, err = conn.ReadMessage()
		if err == nil {
			_ = conn.WriteMessage(websocket.TextMessage, []byte("decode failure at /srv/wadjet/internal/handler.go:42"))
		}
	})
	defer server.Close()
	finding, err := CheckVerboseErrors(context.Background(), target, testConnectionOptions())
	if err != nil {
		t.Fatalf("CheckVerboseErrors() error = %v", err)
	}
	if finding == nil || finding.ID != "verbose-errors" || !strings.Contains(finding.Evidence, "handler.go") {
		t.Fatalf("CheckVerboseErrors() = %#v, want internal-path finding", finding)
	}
}

func echoWebSocketServer(t *testing.T, handler func(http.ResponseWriter, *http.Request)) (*httptest.Server, string) {
	t.Helper()
	if handler == nil {
		handler = func(writer http.ResponseWriter, request *http.Request) {
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			conn, err := upgrader.Upgrade(writer, request, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				messageType, message, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(messageType, message); err != nil {
					return
				}
			}
		}
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	target := "ws" + strings.TrimPrefix(server.URL, "http")
	return server, target
}
