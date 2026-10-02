.PHONY: build test lint run-testserver

build:
	mkdir -p build
	go build -o build/wadjet ./cmd/wadjet

test:
	go test ./...

lint:
	go vet ./...

run-testserver:
	go run ./internal/testserver