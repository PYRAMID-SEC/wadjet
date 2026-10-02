# Contributing

Contributions should preserve Wadjet's focus on authorized, non-destructive
WebSocket security testing.

## Development

- Use Go 1.21 or newer.
- Keep dependencies minimal and prefer the standard library.
- Add focused tests for new checks, rule behavior, and report formats.
- Run `go build ./...`, `go test ./...`, and `go vet ./...` before submitting.
- Keep probes low-volume, bounded, and free of data-modifying behavior.
- Bind local test services to loopback; never add automatic target discovery.

## Pull Requests

Describe the behavior changed, the security rationale, and the tests run. Do
not include credentials, private target data, or exploit payloads in examples.