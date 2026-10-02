package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pyramidsec/wadjet/internal/checks"
	"github.com/pyramidsec/wadjet/internal/scanner"
)

func TestVulnerableServerFindsBuiltInIssues(t *testing.T) {
	server := httptest.NewServer(Handler())
	defer server.Close()
	target := "ws" + strings.TrimPrefix(server.URL, "http") + "/socket?token=example-value"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	options := scanner.ConnectionOptions{Timeout: time.Second}

	origin, err := checks.CheckOriginValidation(ctx, target, options)
	if err != nil || origin == nil {
		t.Fatalf("origin check = (%#v, %v), want finding", origin, err)
	}
	noAuth, err := checks.CheckNoAuth(ctx, target, options)
	if err != nil || noAuth == nil {
		t.Fatalf("no-auth check = (%#v, %v), want finding", noAuth, err)
	}
	if token := checks.CheckTokenInURL(target); token == nil {
		t.Fatal("token-in-url check found no finding")
	}
	if transport := checks.CheckInsecureTransport(target); transport == nil {
		t.Fatal("insecure-transport check found no finding")
	}
	limited, err := checks.CheckRateLimit(ctx, target, options, 3)
	if err != nil || limited == nil {
		t.Fatalf("rate-limit check = (%#v, %v), want finding", limited, err)
	}
	sized, err := checks.CheckMessageSize(ctx, target, options)
	if err != nil || sized == nil {
		t.Fatalf("message-size check = (%#v, %v), want finding", sized, err)
	}
	verbose, err := checks.CheckVerboseErrors(ctx, target, options)
	if err != nil || verbose == nil {
		t.Fatalf("verbose-errors check = (%#v, %v), want finding", verbose, err)
	}
}
