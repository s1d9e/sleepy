# Sleepy — build & dev workflow.

GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -X main.version=$(VERSION)

BIN     := bin
SERVER  := $(BIN)/sleepy-server
CLIENT  := $(BIN)/sleepy-client

.PHONY: all build server client test race vet lint clean docker

all: build

build: server client

server:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(SERVER) ./cmd/server

client:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(CLIENT) ./cmd/client

test:
	$(GO) test ./... -count=1

race:
	$(GO) test ./... -count=1 -race

vet:
	$(GO) vet ./...

# golangci-lint if installed; otherwise fall back to go vet.
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed; running go vet instead"; \
		$(GO) vet ./...; \
	fi

docker:
	docker build -t sleepy:$(VERSION) .

clean:
	rm -rf $(BIN)
