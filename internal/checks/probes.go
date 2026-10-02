package checks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pyramidsec/wadjet/internal/scanner"
)

const (
	// DefaultRateLimitCount is the maximum burst sent by the rate-limit check.
	DefaultRateLimitCount = 50
	// MaxProbeMessageBytes is the payload size used by the message-size check.
	MaxProbeMessageBytes = 1 << 20
	rateObserveWindow    = 250 * time.Millisecond
)

var verboseErrorPattern = regexp.MustCompile(`(?i)(stack\s*trace|goroutine\s+\d+|panic:|/[[:alnum:]_.-]+(/[[:alnum:]_.-]+)+\.(go|php|py|js|java)(:[0-9]+)?)`)

// CheckRateLimit sends a bounded burst of small, non-mutating JSON messages.
func CheckRateLimit(ctx context.Context, target string, options scanner.ConnectionOptions, count int) (*Finding, error) {
	if count <= 0 {
		count = DefaultRateLimitCount
	}
	if count > DefaultRateLimitCount {
		count = DefaultRateLimitCount
	}
	conn, response, err := scanner.Connect(ctx, target, options)
	if err != nil {
		closeResponse(response)
		return nil, fmt.Errorf("rate-limit handshake: %w", err)
	}
	defer conn.Close()
	conn.SetReadLimit(64 * 1024)
	for index := 0; index < count; index++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := conn.SetWriteDeadline(operationDeadline(ctx, options.Timeout, 0)); err != nil {
			return nil, err
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"probe":"wadjet-rate"}`)); err != nil {
			return nil, nil
		}
	}

	deadline := operationDeadline(ctx, options.Timeout, rateObserveWindow)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	for index := 0; index < count+1; index++ {
		_, _, err := conn.ReadMessage()
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if isTimeout(err) {
			return rateLimitFinding(count), nil
		}
		return nil, nil
	}
	return rateLimitFinding(count), nil
}

// CheckMessageSize sends one 1 MiB valid JSON message and checks whether it is accepted.
func CheckMessageSize(ctx context.Context, target string, options scanner.ConnectionOptions) (*Finding, error) {
	conn, response, err := scanner.Connect(ctx, target, options)
	if err != nil {
		closeResponse(response)
		return nil, fmt.Errorf("message-size handshake: %w", err)
	}
	defer conn.Close()
	conn.SetReadLimit(MaxProbeMessageBytes + 1024)
	payload := []byte(`{"probe":"` + strings.Repeat("a", MaxProbeMessageBytes-12) + `"}`)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := conn.SetWriteDeadline(operationDeadline(ctx, options.Timeout, 0)); err != nil {
		return nil, err
	}
	if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
		return nil, nil
	}
	accepted, err := observeAcceptance(ctx, conn, options.Timeout)
	if err != nil || !accepted {
		return nil, err
	}
	return &Finding{
		ID:          "message-size",
		Title:       "WebSocket accepts an oversized message",
		Severity:    SeverityMedium,
		Description: "The server accepted a 1 MiB WebSocket message without closing the connection or rejecting the frame.",
		Evidence:    "A 1 MiB JSON probe was written and the connection remained open or returned a response.",
		Remediation: "Set an application-appropriate maximum message size and reject larger frames before processing them.",
	}, nil
}

// CheckVerboseErrors sends one malformed JSON frame and looks for internal diagnostics.
func CheckVerboseErrors(ctx context.Context, target string, options scanner.ConnectionOptions) (*Finding, error) {
	conn, response, err := scanner.Connect(ctx, target, options)
	if err != nil {
		closeResponse(response)
		return nil, fmt.Errorf("verbose-errors handshake: %w", err)
	}
	defer conn.Close()
	conn.SetReadLimit(64 * 1024)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := conn.SetWriteDeadline(operationDeadline(ctx, options.Timeout, 0)); err != nil {
		return nil, err
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"`)); err != nil {
		return nil, nil
	}
	if err := conn.SetReadDeadline(operationDeadline(ctx, options.Timeout, 0)); err != nil {
		return nil, err
	}
	_, payload, err := conn.ReadMessage()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil
	}
	match := verboseErrorPattern.Find(payload)
	if match == nil {
		return nil, nil
	}
	evidence := strings.TrimSpace(string(payload))
	if len(evidence) > 250 {
		evidence = evidence[:250] + "..."
	}
	return &Finding{
		ID:          "verbose-errors",
		Title:       "WebSocket response exposes internal error details",
		Severity:    SeverityLow,
		Description: "A malformed JSON message produced a response containing a stack trace, runtime diagnostic, or source path.",
		Evidence:    evidence,
		Remediation: "Return a generic client-facing error and keep detailed diagnostics in access-controlled server logs.",
	}, nil
}

func rateLimitFinding(count int) *Finding {
	return &Finding{
		ID:          "rate-limit",
		Title:       "WebSocket endpoint did not throttle a message burst",
		Severity:    SeverityMedium,
		Description: "The endpoint accepted a burst of small messages without an observed throttle or connection close.",
		Evidence:    fmt.Sprintf("%d small JSON messages were sent without an observed throttle or close.", count),
		Remediation: "Apply per-connection and per-user message rate limits, and close connections that exceed them.",
	}
}

func observeAcceptance(ctx context.Context, conn *websocket.Conn, timeout time.Duration) (bool, error) {
	if err := conn.SetReadDeadline(operationDeadline(ctx, timeout, rateObserveWindow)); err != nil {
		return false, err
	}
	_, _, err := conn.ReadMessage()
	if err == nil {
		return true, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if isTimeout(err) {
		return true, nil
	}
	return false, nil
}

func operationDeadline(ctx context.Context, timeout, maxWindow time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if maxWindow > 0 {
		windowDeadline := time.Now().Add(maxWindow)
		if windowDeadline.Before(deadline) {
			deadline = windowDeadline
		}
	}
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return deadline
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.Is(err, io.EOF) == false && errors.As(err, &netErr) && netErr.Timeout()
}
