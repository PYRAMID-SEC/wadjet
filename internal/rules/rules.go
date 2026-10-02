package rules

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pyramidsec/wadjet/internal/checks"
	"github.com/pyramidsec/wadjet/internal/scanner"
	"gopkg.in/yaml.v3"
)

const (
	maxRuleMessages    = 10
	maxRuleMessageSize = 4096
	maxRuleResponse    = 64 * 1024
)

var ruleIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// Rule describes a single declarative WebSocket security check.
type Rule struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Request     Request  `yaml:"request"`
	Matchers    Matchers `yaml:"matchers"`
	Remediation string   `yaml:"remediation"`
}

// Request contains the handshake headers and bounded messages sent by a rule.
type Request struct {
	Headers  map[string]string `yaml:"headers"`
	Messages []string          `yaml:"messages"`
}

// Matchers contains optional conditions that are ANDed when present.
type Matchers struct {
	Status       *int   `yaml:"status"`
	BodyContains string `yaml:"body-contains"`
	Regex        string `yaml:"regex"`
}

// LoadDir parses and validates all YAML rule files in a directory.
func LoadDir(directory string) ([]Rule, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read rules directory %q: %w", directory, err)
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yaml" || ext == ".yml" {
			paths = append(paths, filepath.Join(directory, entry.Name()))
		}
	}
	sort.Strings(paths)
	var loaded []Rule
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read rule file %q: %w", path, err)
		}
		var rule Rule
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&rule); err != nil {
			return nil, fmt.Errorf("parse rule file %q: %w", path, err)
		}
		if err := validateRule(rule); err != nil {
			return nil, fmt.Errorf("invalid rule file %q: %w", path, err)
		}
		loaded = append(loaded, rule)
	}
	return loaded, nil
}

// Validate checks that a rule is well-formed and bounded for safe execution.
func Validate(rule Rule) error {
	return validateRule(rule)
}

func validateRule(rule Rule) error {
	if !ruleIDPattern.MatchString(rule.ID) {
		return fmt.Errorf("id must contain 1-64 letters, digits, dots, underscores, or hyphens")
	}
	if strings.TrimSpace(rule.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if rule.Severity != string(checks.SeverityHigh) && rule.Severity != string(checks.SeverityMedium) && rule.Severity != string(checks.SeverityLow) {
		return fmt.Errorf("severity must be high, medium, or low")
	}
	if strings.TrimSpace(rule.Description) == "" {
		return fmt.Errorf("description is required")
	}
	if strings.TrimSpace(rule.Remediation) == "" {
		return fmt.Errorf("remediation is required")
	}
	if len(rule.Request.Messages) > maxRuleMessages {
		return fmt.Errorf("request.messages cannot contain more than %d entries", maxRuleMessages)
	}
	for index, message := range rule.Request.Messages {
		if len(message) > maxRuleMessageSize {
			return fmt.Errorf("request.messages[%d] exceeds %d bytes", index, maxRuleMessageSize)
		}
	}
	for name, value := range rule.Request.Headers {
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\r\n:") || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("request.headers contains an invalid header")
		}
	}
	if rule.Matchers.Status == nil && rule.Matchers.BodyContains == "" && rule.Matchers.Regex == "" {
		return fmt.Errorf("at least one matcher is required")
	}
	if rule.Matchers.Status != nil && (*rule.Matchers.Status < 100 || *rule.Matchers.Status > 599) {
		return fmt.Errorf("matchers.status must be between 100 and 599")
	}
	if rule.Matchers.Regex != "" {
		if _, err := regexp.Compile(rule.Matchers.Regex); err != nil {
			return fmt.Errorf("matchers.regex is invalid: %w", err)
		}
	}
	return nil
}

// Run executes a rule against only the supplied WebSocket target.
func Run(ctx context.Context, target string, rule Rule, options scanner.ConnectionOptions) (*checks.Finding, error) {
	if err := validateRule(rule); err != nil {
		return nil, err
	}
	if err := scanner.ValidateURL(target); err != nil {
		return nil, err
	}
	headers := options.Header.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	for name, value := range rule.Request.Headers {
		headers.Set(name, value)
	}
	options.Header = headers
	conn, response, err := scanner.Connect(ctx, target, options)
	status := 0
	var responseBody []byte
	if response != nil {
		status = response.StatusCode
	}
	if err != nil {
		if response != nil && response.Body != nil {
			responseBody, _ = io.ReadAll(io.LimitReader(response.Body, maxRuleResponse))
			_ = response.Body.Close()
		}
	} else {
		defer conn.Close()
		if status == 0 {
			status = http.StatusSwitchingProtocols
		}
		for _, message := range rule.Request.Messages {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if err := conn.SetWriteDeadline(ruleDeadline(ctx, options.Timeout)); err != nil {
				return nil, err
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
				break
			}
			if err := conn.SetReadDeadline(ruleDeadline(ctx, options.Timeout)); err != nil {
				return nil, err
			}
			_, payload, readErr := conn.ReadMessage()
			if readErr != nil {
				break
			}
			remaining := maxRuleResponse - len(responseBody)
			if remaining > 0 {
				if len(payload) > remaining {
					payload = payload[:remaining]
				}
				responseBody = append(responseBody, payload...)
			}
		}
	}
	matched, err := rule.Matches(status, responseBody)
	if err != nil || !matched {
		return nil, err
	}
	return &checks.Finding{
		ID:          rule.ID,
		Title:       rule.Name,
		Severity:    checks.Severity(rule.Severity),
		Description: rule.Description,
		Evidence:    fmt.Sprintf("Rule matched target response (HTTP status %d).", status),
		Remediation: rule.Remediation,
	}, nil
}

func ruleDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return deadline
}

// Matches evaluates all configured matchers against a status and response body.
func (rule Rule) Matches(status int, body []byte) (bool, error) {
	if rule.Matchers.Status != nil && status != *rule.Matchers.Status {
		return false, nil
	}
	if rule.Matchers.BodyContains != "" && !bytes.Contains(body, []byte(rule.Matchers.BodyContains)) {
		return false, nil
	}
	if rule.Matchers.Regex != "" {
		compiled, err := regexp.Compile(rule.Matchers.Regex)
		if err != nil {
			return false, fmt.Errorf("compile rule matcher: %w", err)
		}
		if !compiled.Match(body) {
			return false, nil
		}
	}
	return true, nil
}
