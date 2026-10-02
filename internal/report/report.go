package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/pyramidsec/wadjet/internal/checks"
)

// WriteJSON writes findings as an indented JSON array.
func WriteJSON(writer io.Writer, findings []checks.Finding) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(findings)
}

// WriteMarkdown writes a summary table and one details section per finding.
func WriteMarkdown(writer io.Writer, findings []checks.Finding) error {
	ordered := sortedFindings(findings)
	if _, err := fmt.Fprintln(writer, "| Severity | ID | Finding |\n| --- | --- | --- |"); err != nil {
		return err
	}
	for _, finding := range ordered {
		if _, err := fmt.Fprintf(writer, "| %s | `%s` | %s |\n", finding.Severity, escapeTable(finding.ID), escapeTable(finding.Title)); err != nil {
			return err
		}
	}
	for _, finding := range ordered {
		if _, err := fmt.Fprintf(writer, "\n## %s\n\n- **ID:** `%s`\n- **Severity:** %s\n- **Description:** %s\n- **Evidence:** %s\n- **Remediation:** %s\n", finding.Title, finding.ID, finding.Severity, finding.Description, finding.Evidence, finding.Remediation); err != nil {
			return err
		}
	}
	return nil
}

// WriteSARIF writes findings in SARIF 2.1.0 format.
func WriteSARIF(writer io.Writer, findings []checks.Finding) error {
	type rule struct {
		ID               string `json:"id"`
		ShortDescription struct {
			Text string `json:"text"`
		} `json:"shortDescription"`
		Help struct {
			Text string `json:"text"`
		} `json:"help"`
	}
	type result struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		} `json:"locations,omitempty"`
		Properties map[string]string `json:"properties"`
	}
	type run struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Rules   []rule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []result `json:"results"`
	}
	document := struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []run  `json:"runs"`
	}{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json"}
	current := run{}
	current.Tool.Driver.Name = "Wadjet"
	current.Tool.Driver.Version = "1.0.0"
	ordered := sortedFindings(findings)
	seen := make(map[string]struct{}, len(ordered))
	for _, finding := range ordered {
		if _, exists := seen[finding.ID]; !exists {
			item := rule{ID: finding.ID}
			item.ShortDescription.Text = finding.Title
			item.Help.Text = finding.Remediation
			current.Tool.Driver.Rules = append(current.Tool.Driver.Rules, item)
			seen[finding.ID] = struct{}{}
		}
		item := result{RuleID: finding.ID, Level: sarifLevel(finding.Severity), Properties: map[string]string{
			"severity":    string(finding.Severity),
			"description": finding.Description,
			"evidence":    finding.Evidence,
			"remediation": finding.Remediation,
		}}
		item.Message.Text = finding.Title + ": " + finding.Evidence
		current.Results = append(current.Results, item)
	}
	document.Runs = []run{current}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

// WriteTerminal prints findings with severity colors and a summary line.
func WriteTerminal(writer io.Writer, findings []checks.Finding, color bool) error {
	ordered := sortedFindings(findings)
	counts := map[checks.Severity]int{}
	for _, finding := range ordered {
		counts[finding.Severity]++
		label := strings.ToUpper(string(finding.Severity))
		if color {
			label = colorize(label, finding.Severity)
		}
		if _, err := fmt.Fprintf(writer, "[%s] %s: %s\n", label, finding.ID, finding.Title); err != nil {
			return err
		}
		if finding.Evidence != "" {
			if _, err := fmt.Fprintf(writer, "  Evidence: %s\n", finding.Evidence); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(writer, "Summary: %d finding(s) (%d high, %d medium, %d low)\n", len(ordered), counts[checks.SeverityHigh], counts[checks.SeverityMedium], counts[checks.SeverityLow])
	return err
}

func sortedFindings(findings []checks.Finding) []checks.Finding {
	ordered := append([]checks.Finding(nil), findings...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return severityRank(ordered[i].Severity) < severityRank(ordered[j].Severity)
	})
	return ordered
}

func severityRank(severity checks.Severity) int {
	switch severity {
	case checks.SeverityHigh:
		return 0
	case checks.SeverityMedium:
		return 1
	case checks.SeverityLow:
		return 2
	default:
		return 3
	}
}

func sarifLevel(severity checks.Severity) string {
	switch severity {
	case checks.SeverityHigh:
		return "error"
	case checks.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func colorize(value string, severity checks.Severity) string {
	code := "33"
	switch severity {
	case checks.SeverityHigh:
		code = "31"
	case checks.SeverityMedium:
		code = "38;5;208"
	}
	return "\x1b[" + code + "m" + value + "\x1b[0m"
}

func escapeTable(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	return strings.ReplaceAll(value, "\n", " ")
}
