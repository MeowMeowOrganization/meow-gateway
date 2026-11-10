GO ?= go
BINARY := bin/meow-gateway

.PHONY: run build test test-race vet fmt check clean

run:
	$(GO) run ./cmd/gateway

build:
	mkdir -p bin
	$(GO) build -trimpath -o $(BINARY) ./cmd/gateway

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

check: test test-race vet

clean:
	rm -rf bin
