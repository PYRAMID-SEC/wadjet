package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pyramidsec/wadjet/internal/scanner"
)

func TestLoadDirValidatesAndSortsRules(t *testing.T) {
	directory := t.TempDir()
	writeRule(t, directory, "b.yaml", validRuleYAML("second"))
	writeRule(t, directory, "a.yml", validRuleYAML("first"))
	writeRule(t, directory, "ignored.txt", "not: yaml")
	rules, err := LoadDir(directory)
	if err != nil {
		t.Fatalf("LoadDir() error = %v", err)
	}
	if len(rules) != 2 || rules[0].ID != "first" || rules[1].ID != "second" {
		t.Fatalf("LoadDir() IDs = %#v, want [first second]", rules)
	}
}

func TestLoadDirReportsInvalidRule(t *testing.T) {
	directory := t.TempDir()
	writeRule(t, directory, "broken.yaml", "id: bad id\n")
	_, err := LoadDir(directory)
	if err == nil || !strings.Contains(err.Error(), "broken.yaml") || !strings.Contains(err.Error(), "id") {
		t.Fatalf("LoadDir() error = %v, want file and field context", err)
	}
}

func TestValidateRejectsUnsafeMessageBounds(t *testing.T) {
	rule := Rule{ID: "bounded", Name: "Bounded", Severity: "low", Description: "desc", Remediation: "fix", Matchers: Matchers{BodyContains: "ok"}}
	rule.Request.Messages = make([]string, maxRuleMessages+1)
	if err := Validate(rule); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("Validate() error = %v, want message count limit", err)
	}
}

func TestRunMatchesWebSocketResponse(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _, err = conn.ReadMessage()
		if err == nil {
			_ = conn.WriteMessage(websocket.TextMessage, []byte("rule marker"))
		}
	}))
	defer server.Close()
	target := "ws" + strings.TrimPrefix(server.URL, "http")
	rule := Rule{
		ID: "echo-marker", Name: "Echo marker", Severity: "medium", Description: "Test response", Remediation: "No fix",
		Request:  Request{Messages: []string{`{"probe":"wadjet"}`}},
		Matchers: Matchers{Status: intPointer(http.StatusSwitchingProtocols), BodyContains: "rule marker"},
	}
	finding, err := Run(context.Background(), target, rule, scanner.ConnectionOptions{Timeout: time.Second})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if finding == nil || finding.ID != rule.ID {
		t.Fatalf("Run() = %#v, want matching finding", finding)
	}
}

func TestMatchesRequiresEveryConfiguredMatcher(t *testing.T) {
	status := http.StatusSwitchingProtocols
	rule := Rule{Matchers: Matchers{Status: &status, BodyContains: "expected", Regex: "^expected$"}}
	matched, err := rule.Matches(status, []byte("expected"))
	if err != nil || !matched {
		t.Fatalf("Matches() = (%v, %v), want (true, nil)", matched, err)
	}
	matched, err = rule.Matches(status, []byte("other"))
	if err != nil || matched {
		t.Fatalf("Matches() = (%v, %v), want (false, nil)", matched, err)
	}
}

func writeRule(t *testing.T, directory, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func validRuleYAML(id string) string {
	return "id: " + id + "\nname: Example\nseverity: low\ndescription: Test\nremediation: Fix\nmatchers:\n  body-contains: marker\n"
}

func intPointer(value int) *int {
	return &value
}
