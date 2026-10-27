GO        ?= go
BIN       ?= bin/claymod
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -ldflags "-X github.com/claymod/claymod/internal/cli.version=$(VERSION)"

.PHONY: all build test test-full check fmt vet tidy clean

all: build

build:
	$(GO) build $(LDFLAGS) -o $(BIN) ./cmd/claymod

test:
	$(GO) test ./...

test-full:
	$(GO) test -count=1 ./...

fmt:
	gofmt -l -w cmd internal

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

check: fmt vet test
	$(GO) test -race ./...

clean:
	rm -rf bin/
