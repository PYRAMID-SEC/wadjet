package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/pyramidsec/wadjet/internal/scanner"
)

// Severity identifies the impact level of a security finding.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// Finding is a security issue detected by a built-in or YAML-defined check.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
}

// CheckOriginValidation reports when the server accepts an untrusted Origin.
func CheckOriginValidation(ctx context.Context, target string, options scanner.ConnectionOptions) (*Finding, error) {
	headers := cloneHeaders(options.Header)
	headers.Set("Origin", "https://evil.example")
	options.Header = headers
	conn, response, err := scanner.Connect(ctx, target, options)
	if err != nil {
		closeResponse(response)
		if response == nil {
			return nil, fmt.Errorf("origin-validation handshake: %w", err)
		}
		return nil, nil
	}
	defer conn.Close()
	return &Finding{
		ID:          "origin-validation",
		Title:       "WebSocket handshake accepts an untrusted Origin",
		Severity:    SeverityHigh,
		Description: "The server accepted a WebSocket connection from an untrusted Origin, which may enable Cross-Site WebSocket Hijacking when browser credentials are present.",
		Evidence:    "Handshake accepted Origin https://evil.example with HTTP 101 Switching Protocols.",
		Remediation: "Validate the Origin header against an explicit allowlist before upgrading the connection.",
	}, nil
}

// CheckNoAuth reports when the server accepts a connection without standard credentials.
func CheckNoAuth(ctx context.Context, target string, options scanner.ConnectionOptions) (*Finding, error) {
	headers := cloneHeaders(options.Header)
	headers.Del("Authorization")
	headers.Del("Proxy-Authorization")
	headers.Del("Cookie")
	options.Header = headers
	conn, response, err := scanner.Connect(ctx, target, options)
	if err != nil {
		closeResponse(response)
		if response == nil {
			return nil, fmt.Errorf("no-auth handshake: %w", err)
		}
		return nil, nil
	}
	defer conn.Close()
	return &Finding{
		ID:          "no-auth",
		Title:       "WebSocket endpoint allows unauthenticated access",
		Severity:    SeverityHigh,
		Description: "The server accepted a WebSocket connection without Authorization or Cookie headers.",
		Evidence:    "Handshake accepted without Authorization, Proxy-Authorization, or Cookie headers.",
		Remediation: "Require and validate an authenticated identity before upgrading the WebSocket connection.",
	}, nil
}

// CheckTokenInURL reports sensitive-looking query parameter names without exposing their values.
func CheckTokenInURL(target string) *Finding {
	parsed, err := url.ParseRequestURI(target)
	if err != nil {
		return nil
	}
	sensitiveNames := map[string]struct{}{
		"access_token": {}, "api_key": {}, "apikey": {}, "auth": {},
		"key": {}, "refresh_token": {}, "secret": {}, "signature": {}, "token": {},
	}
	var names []string
	for name := range parsed.Query() {
		if _, found := sensitiveNames[strings.ToLower(name)]; found {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return &Finding{
		ID:          "token-in-url",
		Title:       "Possible credential in WebSocket URL query",
		Severity:    SeverityMedium,
		Description: "Sensitive-looking query parameters can leak through logs, browser history, and monitoring systems.",
		Evidence:    "Sensitive query parameter name(s) present: " + strings.Join(names, ", ") + "; values redacted.",
		Remediation: "Send credentials through an authenticated handshake header or another protected mechanism instead of the URL.",
	}
}

// CheckInsecureTransport reports a WebSocket URL that does not use TLS.
func CheckInsecureTransport(target string) *Finding {
	parsed, err := url.ParseRequestURI(target)
	if err != nil || parsed.Scheme != "ws" {
		return nil
	}
	return &Finding{
		ID:          "insecure-transport",
		Title:       "WebSocket connection does not use TLS",
		Severity:    SeverityMedium,
		Description: "The ws:// transport does not encrypt WebSocket data in transit.",
		Evidence:    "Target URL uses the ws:// scheme.",
		Remediation: "Serve the endpoint over wss:// with a valid TLS certificate.",
	}
}

func cloneHeaders(headers http.Header) http.Header {
	if headers == nil {
		return make(http.Header)
	}
	return headers.Clone()
}

func closeResponse(response *http.Response) {
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
}
