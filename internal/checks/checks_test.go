package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pyramidsec/wadjet/internal/scanner"
)

func TestCheckOriginValidation(t *testing.T) {
	server, target := permissiveWebSocketServer(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Origin") != "https://evil.example" {
			t.Errorf("Origin = %q, want evil origin", request.Header.Get("Origin"))
		}
	})
	defer server.Close()

	finding, err := CheckOriginValidation(context.Background(), target, testConnectionOptions())
	if err != nil {
		t.Fatalf("CheckOriginValidation() error = %v", err)
	}
	if finding == nil || finding.ID != "origin-validation" || finding.Severity != SeverityHigh {
		t.Fatalf("CheckOriginValidation() = %#v, want high origin-validation finding", finding)
	}
}

func TestCheckNoAuthStripsStandardCredentials(t *testing.T) {
	server, target := permissiveWebSocketServer(t, func(writer http.ResponseWriter, request *http.Request) {
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
			if got := request.Header.Get(name); got != "" {
				t.Errorf("server received %s = %q", name, got)
			}
		}
	})
	defer server.Close()

	options := testConnectionOptions()
	options.Header = http.Header{
		"Authorization":       []string{"Bearer test-value"},
		"Proxy-Authorization": []string{"Basic test-value"},
		"Cookie":              []string{"session=test-value"},
	}
	finding, err := CheckNoAuth(context.Background(), target, options)
	if err != nil {
		t.Fatalf("CheckNoAuth() error = %v", err)
	}
	if finding == nil || finding.ID != "no-auth" || finding.Severity != SeverityHigh {
		t.Fatalf("CheckNoAuth() = %#v, want high no-auth finding", finding)
	}
}

func TestCheckTokenInURL(t *testing.T) {
	finding := CheckTokenInURL("wss://example.test/socket?access_token=private&room=general")
	if finding == nil || finding.ID != "token-in-url" || finding.Severity != SeverityMedium {
		t.Fatalf("CheckTokenInURL() = %#v, want medium token-in-url finding", finding)
	}
	if strings.Contains(finding.Evidence, "private") {
		t.Fatal("finding evidence exposed the query value")
	}
	if finding := CheckTokenInURL("wss://example.test/socket?room=general"); finding != nil {
		t.Fatalf("CheckTokenInURL() = %#v, want no finding", finding)
	}
}

func TestCheckInsecureTransport(t *testing.T) {
	if finding := CheckInsecureTransport("ws://example.test/socket"); finding == nil || finding.ID != "insecure-transport" {
		t.Fatalf("CheckInsecureTransport(ws) = %#v, want finding", finding)
	}
	if finding := CheckInsecureTransport("wss://example.test/socket"); finding != nil {
		t.Fatalf("CheckInsecureTransport(wss) = %#v, want no finding", finding)
	}
}

func permissiveWebSocketServer(t *testing.T, observe func(http.ResponseWriter, *http.Request)) (*httptest.Server, string) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if observe != nil {
			observe(writer, request)
		}
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		_ = conn.Close()
	}))
	target := "ws" + strings.TrimPrefix(server.URL, "http")
	return server, target
}

func testConnectionOptions() scanner.ConnectionOptions {
	return scanner.ConnectionOptions{Timeout: time.Second}
}
