APP := bifrost
SERVER_IMAGE ?= $(APP)-server:local
GO ?= go
GOCACHE ?= /tmp/$(APP)-gocache
BIN_DIR ?= bin
PODMAN ?= podman
GOFLAGS ?= -buildvcs=false -trimpath
LDFLAGS ?= -s -w

.PHONY: all fmt test build client server image clean

all: fmt test build

fmt:
	gofmt -w cmd internal pkg

test:
	GOCACHE=$(GOCACHE) $(GO) test ./...

build: client server

client:
	mkdir -p $(BIN_DIR)
	GOCACHE=$(GOCACHE) CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o $(BIN_DIR)/$(APP)-client ./cmd/client

server:
	mkdir -p $(BIN_DIR)
	GOCACHE=$(GOCACHE) CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o $(BIN_DIR)/$(APP)-server ./cmd/server

image:
	$(PODMAN) build -t $(SERVER_IMAGE) .

clean:
	rm -rf $(BIN_DIR)
