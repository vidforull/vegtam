# Commits in this repository carry UTC timestamps. Commit with:
#
#   TZ=UTC git commit
#
# Override the version with: make build VERSION=v0.1.0

BINARY  := vegtam
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -X main.version=$(VERSION)

.PHONY: build test vet fmt lint clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/vegtam

test:
	go test ./...

vet:
	go vet ./...

# Fails if any Go file needs gofmt; does not rewrite files.
fmt:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, skipping lint"; \
	fi

clean:
	rm -f $(BINARY) coverage.out
	rm -rf bin dist
