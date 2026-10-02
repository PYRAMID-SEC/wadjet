package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pyramidsec/wadjet/internal/checks"
)

func TestWriteJSON(t *testing.T) {
	var output bytes.Buffer
	if err := WriteJSON(&output, []checks.Finding{sampleFinding()}); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}
	var decoded []checks.Finding
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON output invalid: %v", err)
	}
	if len(decoded) != 1 || decoded[0].ID != "origin-validation" {
		t.Fatalf("decoded findings = %#v", decoded)
	}
}

func TestWriteMarkdownIncludesTableAndDetails(t *testing.T) {
	var output bytes.Buffer
	if err := WriteMarkdown(&output, []checks.Finding{sampleFinding()}); err != nil {
		t.Fatalf("WriteMarkdown() error = %v", err)
	}
	for _, expected := range []string{"| Severity | ID | Finding |", "## Origin accepted", "Evidence", "Remediation"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("Markdown output missing %q", expected)
		}
	}
}

func TestWriteSARIF(t *testing.T) {
	var output bytes.Buffer
	if err := WriteSARIF(&output, []checks.Finding{sampleFinding()}); err != nil {
		t.Fatalf("WriteSARIF() error = %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("SARIF output invalid JSON: %v", err)
	}
	if document["version"] != "2.1.0" {
		t.Fatalf("SARIF version = %v, want 2.1.0", document["version"])
	}
}

func TestWriteTerminalColorsSeverityAndSummarizes(t *testing.T) {
	var output bytes.Buffer
	if err := WriteTerminal(&output, []checks.Finding{sampleFinding()}, true); err != nil {
		t.Fatalf("WriteTerminal() error = %v", err)
	}
	if !strings.Contains(output.String(), "\x1b[31mHIGH") || !strings.Contains(output.String(), "1 high") {
		t.Fatalf("terminal output missing color or summary: %q", output.String())
	}
}

func sampleFinding() checks.Finding {
	return checks.Finding{
		ID: "origin-validation", Title: "Origin accepted", Severity: checks.SeverityHigh,
		Description: "Origin is not validated", Evidence: "HTTP 101", Remediation: "Check Origin",
	}
}
