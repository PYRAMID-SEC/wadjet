package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

// ConnectionOptions configures a single WebSocket handshake.
type ConnectionOptions struct {
	Header    http.Header
	Timeout   time.Duration
	TLSConfig *tls.Config
}

// ValidateURL accepts only absolute ws:// and wss:// URLs with a host.
func ValidateURL(target string) error {
	parsed, err := url.ParseRequestURI(target)
	if err != nil {
		return fmt.Errorf("invalid WebSocket URL: %w", err)
	}
	if parsed.Scheme != "ws" && parsed.Scheme != "wss" {
		return fmt.Errorf("unsupported URL scheme %q: use ws or wss", parsed.Scheme)
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("invalid WebSocket URL: host is required")
	}
	return nil
}

// Connect opens a WebSocket connection to exactly the supplied target URL.
func Connect(ctx context.Context, target string, options ConnectionOptions) (*websocket.Conn, *http.Response, error) {
	if err := ValidateURL(target); err != nil {
		return nil, nil, err
	}
	if options.Timeout <= 0 {
		return nil, nil, fmt.Errorf("connection timeout must be positive")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = options.Timeout
	if options.TLSConfig != nil {
		dialer.TLSClientConfig = options.TLSConfig.Clone()
	}
	conn, response, err := dialer.DialContext(ctx, target, options.Header.Clone())
	if err != nil {
		return nil, response, err
	}
	return conn, response, nil
}
