package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pyramidsec/wadjet/internal/checks"
	"github.com/pyramidsec/wadjet/internal/report"
	"github.com/pyramidsec/wadjet/internal/rules"
	"github.com/pyramidsec/wadjet/internal/scanner"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	if err := newRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "wadjet",
		Short:         "A WebSocket security scanner for authorized testing",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newScanCommand(), &cobra.Command{
		Use:   "version",
		Short: "Print the Wadjet version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	})
	return root
}

func newScanCommand() *cobra.Command {
	var headers []string
	var checksFlag string
	var rulesDir string
	var output string
	var format string
	var timeout time.Duration
	var rateLimitCount int
	var insecure bool
	var verbose bool

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan one WebSocket URL for security issues",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.ErrOrStderr(), "LEGAL NOTICE: Only test systems you own or have explicit permission to test.")
			target, err := cmd.Flags().GetString("url")
			if err != nil {
				return err
			}
			if err := scanner.ValidateURL(target); err != nil {
				return err
			}
			if format != "json" && format != "markdown" && format != "sarif" {
				return fmt.Errorf("unsupported format %q: use json, markdown, or sarif", format)
			}
			if timeout <= 0 {
				return fmt.Errorf("timeout must be positive")
			}
			if rateLimitCount <= 0 {
				return fmt.Errorf("rate-limit-count must be positive")
			}
			requestHeaders, err := parseHeaders(headers)
			if err != nil {
				return err
			}
			selectedChecks, err := selectChecks(checksFlag)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			options := scanner.ConnectionOptions{
				Header:    requestHeaders,
				Timeout:   timeout,
				TLSConfig: &tls.Config{InsecureSkipVerify: insecure},
			}
			var findings []checks.Finding
			for _, checkID := range selectedChecks {
				if verbose {
					fmt.Fprintf(cmd.ErrOrStderr(), "Running check %s against %s\n", checkID, target)
				}
				finding, err := runCheck(ctx, checkID, target, options, rateLimitCount)
				if err != nil {
					return fmt.Errorf("check %s: %w", checkID, err)
				}
				if finding != nil {
					findings = append(findings, *finding)
				}
			}
			if rulesDir != "" {
				loaded, err := rules.LoadDir(rulesDir)
				if err != nil {
					return err
				}
				for _, rule := range loaded {
					if verbose {
						fmt.Fprintf(cmd.ErrOrStderr(), "Running rule %s against %s\n", rule.ID, target)
					}
					finding, err := rules.Run(ctx, target, rule, options)
					if err != nil {
						return fmt.Errorf("rule %s: %w", rule.ID, err)
					}
					if finding != nil {
						findings = append(findings, *finding)
					}
				}
			}
			if err := report.WriteTerminal(cmd.ErrOrStderr(), findings, true); err != nil {
				return fmt.Errorf("write terminal summary: %w", err)
			}
			var destination *os.File
			if output != "" {
				destination, err = os.OpenFile(output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
				if err != nil {
					return fmt.Errorf("open report output: %w", err)
				}
				defer destination.Close()
			} else {
				destination = nil
			}
			writer := cmd.OutOrStdout()
			if destination != nil {
				writer = destination
			}
			if err := writeReport(writer, format, findings); err != nil {
				return fmt.Errorf("write %s report: %w", format, err)
			}
			for _, finding := range findings {
				if finding.Severity == checks.SeverityHigh {
					return fmt.Errorf("high-severity findings detected")
				}
			}
			return nil
		},
	}
	cmd.Flags().StringP("url", "u", "", "WebSocket URL to scan (ws:// or wss://)")
	_ = cmd.MarkFlagRequired("url")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "HTTP handshake header in KEY: VALUE form (repeatable)")
	cmd.Flags().StringVar(&checksFlag, "checks", "", "Comma-separated check IDs to run")
	cmd.Flags().StringVar(&rulesDir, "rules", "", "Directory containing YAML rules")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write report to this path")
	cmd.Flags().StringVar(&format, "format", "markdown", "Report format: json, markdown, or sarif")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "Connection and operation timeout")
	cmd.Flags().IntVar(&rateLimitCount, "rate-limit-count", checks.DefaultRateLimitCount, "Messages in the rate-limit probe (maximum 50)")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "Skip TLS certificate verification")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	return cmd
}

func selectChecks(value string) ([]string, error) {
	all := []string{"origin-validation", "no-auth", "token-in-url", "insecure-transport", "rate-limit", "message-size", "verbose-errors"}
	if strings.TrimSpace(value) == "" {
		return all, nil
	}
	valid := make(map[string]struct{}, len(all))
	for _, id := range all {
		valid[id] = struct{}{}
	}
	selected := make([]string, 0)
	seen := make(map[string]struct{})
	for _, rawID := range strings.Split(value, ",") {
		id := strings.TrimSpace(rawID)
		if _, ok := valid[id]; !ok {
			return nil, fmt.Errorf("unknown check %q", id)
		}
		if _, ok := seen[id]; !ok {
			selected = append(selected, id)
			seen[id] = struct{}{}
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no checks selected")
	}
	return selected, nil
}

func runCheck(ctx context.Context, id, target string, options scanner.ConnectionOptions, rateLimitCount int) (*checks.Finding, error) {
	switch id {
	case "origin-validation":
		return checks.CheckOriginValidation(ctx, target, options)
	case "no-auth":
		return checks.CheckNoAuth(ctx, target, options)
	case "token-in-url":
		return checks.CheckTokenInURL(target), nil
	case "insecure-transport":
		return checks.CheckInsecureTransport(target), nil
	case "rate-limit":
		return checks.CheckRateLimit(ctx, target, options, rateLimitCount)
	case "message-size":
		return checks.CheckMessageSize(ctx, target, options)
	case "verbose-errors":
		return checks.CheckVerboseErrors(ctx, target, options)
	default:
		return nil, fmt.Errorf("unknown check %q", id)
	}
}

func writeReport(writer io.Writer, format string, findings []checks.Finding) error {
	switch format {
	case "json":
		return report.WriteJSON(writer, findings)
	case "markdown":
		return report.WriteMarkdown(writer, findings)
	case "sarif":
		return report.WriteSARIF(writer, findings)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func parseHeaders(values []string) (http.Header, error) {
	headers := make(http.Header)
	for _, value := range values {
		name, content, found := strings.Cut(value, ":")
		name = strings.TrimSpace(name)
		content = strings.TrimSpace(content)
		if !found || name == "" || content == "" {
			return nil, fmt.Errorf("invalid header %q: expected KEY: VALUE", value)
		}
		headers.Add(name, content)
	}
	return headers, nil
}
