GO        ?= go
BIN       ?= bin/claymod
AGENT_BIN ?= bin/claymod-agent
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w
CGO       ?= 0

.PHONY: all build agent agents release test test-full check fmt vet tidy clean

all: build agent

# Control server + full CLI (links the heavy deps).
build:
	CGO_ENABLED=$(CGO) $(GO) build -trimpath \
		-ldflags "$(LDFLAGS) -X github.com/claymod/claymod/internal/cli.version=$(VERSION)" \
		-o $(BIN) ./cmd/claymod

# Standalone host agent: small static binary (agent + enroll + wg-setup).
agent:
	CGO_ENABLED=0 $(GO) build -trimpath \
		-ldflags "$(LDFLAGS) -X main.version=$(VERSION)" \
		-o $(AGENT_BIN) ./cmd/claymod-agent

# Cross-compiled agents for the bootstrap download endpoint
# (claymod serve --agent-bin-dir serves these). Asset names follow
# uname(1) spelling (aarch64) even though Go's GOARCH is arm64.
agents:
	@mkdir -p bin/agents
	@for pair in linux/amd64 linux/arm64 darwin/arm64 darwin/amd64; do \
		os=$${pair%%/*}; goarch=$${pair##*/}; \
		arch=$$(echo $$goarch | sed 's/arm64/aarch64/'); \
		echo "building bin/agents/claymod-agent-$$os-$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$goarch $(GO) build -trimpath \
			-ldflags "$(LDFLAGS) -X main.version=$(VERSION)" \
			-o bin/agents/claymod-agent-$$os-$$arch ./cmd/claymod-agent; \
	done
	@shasum -a 256 bin/agents/claymod-agent-* | sed 's|bin/agents/||'

# Release artifacts: both binaries for the main platforms + SHA256SUMS
# (the format the README install instructions verify against).
release:
	@mkdir -p dist
	@for pair in linux/amd64 linux/arm64 darwin/arm64; do \
		os=$${pair%%/*}; goarch=$${pair##*/}; \
		arch=$$(echo $$goarch | sed 's/arm64/aarch64/'); \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$goarch $(GO) build -trimpath \
			-ldflags "$(LDFLAGS) -X github.com/claymod/claymod/internal/cli.version=$(VERSION)" \
			-o dist/claymod-$$os-$$arch ./cmd/claymod; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$goarch $(GO) build -trimpath \
			-ldflags "$(LDFLAGS) -X main.version=$(VERSION)" \
			-o dist/claymod-agent-$$os-$$arch ./cmd/claymod-agent; \
	done
	@cd dist && shasum -a 256 claymod-* > SHA256SUMS && cat SHA256SUMS

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
	rm -rf bin/ dist/
