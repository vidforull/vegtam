# Commits in this repository carry UTC timestamps. Commit with:
#
#   TZ=UTC git commit
#
# Override the version with: make build VERSION=v0.1.0
#
# The gate: `make check-fast` while working, `make check` before every pull
# request. CONTRIBUTING.md says what each step is for and how to install
# the tools at these versions.

BINARY  := vegtam
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -X main.version=$(VERSION)

GOLANGCI_LINT_VERSION := 2.15.0
GOVULNCHECK_VERSION   := v1.9.0
FUZZTIME              ?= 30s

# Suppressions: //nolint, //exhaustive:ignore, `_ =` and t.Skip in Go files.
BASELINE     := .gate/suppressions.baseline
SUPPRESSIONS := //nolint|//exhaustive:ignore|^[[:space:]]*_(, _)* = |\bt\.Skip
# The files of the gate, which a pull request changes only on its own.
GATE_FILES   := .golangci.yml Makefile .gate

.PHONY: build test vet fmt lint check-fast check suppressions gate-files vuln fuzz tools clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/vegtam

test:
	go test ./...

vet:
	go vet ./...

# Rewrites the Go files as the gate wants them: gofumpt and goimports.
fmt: tools
	golangci-lint fmt ./...

lint: tools
	golangci-lint run ./...

check-fast: lint
	go test -race ./...

check: check-fast suppressions gate-files
	@out="$$(golangci-lint fmt --diff ./... 2>&1)"; rc=$$?; \
	if [ $$rc -ne 0 ] || [ -n "$$out" ]; then echo "$$out"; echo "check: golangci-lint fmt --diff (exit $$rc): run make fmt"; exit 1; fi
	go vet ./...
	go test -race -shuffle=on -count=1 ./...
	@out="$$(go fix -diff ./... 2>&1)"; rc=$$?; \
	if [ $$rc -ne 0 ] || [ -n "$$out" ]; then echo "$$out"; echo "check: go fix -diff (exit $$rc): run go fix ./..."; exit 1; fi
	go mod tidy -diff
	go mod verify
	@$(MAKE) --no-print-directory vuln

# Fails if the Go files hold more suppressions than the baseline. The
# baseline is taken from origin/main when it has one, so that a pull
# request cannot raise it for itself.
suppressions:
	@found=$$(git grep --untracked -nE '$(SUPPRESSIONS)' -- '*.go'); rc=$$?; \
	if [ $$rc -gt 1 ]; then echo "suppressions: git grep failed (exit $$rc)"; exit 1; fi; \
	n=$$(printf '%s\n' "$$found" | grep -c .); \
	if b=$$(git show origin/main:$(BASELINE) 2>/dev/null); then from=origin/main; \
	else b=$$(cat $(BASELINE)); from=$(BASELINE); fi; \
	echo "suppressions: $$n (baseline $$b, from $$from)"; \
	if [ "$$n" -gt "$$b" ]; then \
		printf '%s\n' "$$found"; \
		echo "suppressions: more than the baseline; fix the code, or raise $(BASELINE) in a pull request of its own"; \
		exit 1; \
	fi

# Names the files of the gate that differ from origin/main. It does not
# fail: a person reviews such a change.
gate-files:
	@changed=$$(git diff --name-only origin/main -- $(GATE_FILES) 2>/dev/null); \
	if [ -n "$$changed" ]; then echo "gate files differ from origin/main (review them on their own):"; echo "$$changed"; fi

# govulncheck reads the vulnerability database online. Without the tool
# the step is skipped, and says so.
vuln:
	@if ! command -v govulncheck >/dev/null 2>&1; then \
		echo "SKIPPED govulncheck: not installed (go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION))"; \
	else \
		v=$$(govulncheck -version | sed -n 's/^Scanner: govulncheck@//p'); \
		if [ "$$v" != "$(GOVULNCHECK_VERSION)" ]; then \
			echo "govulncheck $$v found, the gate wants $(GOVULNCHECK_VERSION)"; exit 1; \
		fi; \
		echo "govulncheck ./..."; govulncheck ./...; \
	fi

# Runs each fuzz target for FUZZTIME. A failing input lands in the
# package's testdata/fuzz; fix the bug and commit the input with the fix.
fuzz:
	go test -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME) ./internal/core/httpfile
	go test -run '^$$' -fuzz '^FuzzParseTemplate$$' -fuzztime $(FUZZTIME) ./internal/core
	go test -run '^$$' -fuzz '^FuzzMasker$$' -fuzztime $(FUZZTIME) ./internal/core
	go test -run '^$$' -fuzz '^FuzzMaskJSON$$' -fuzztime $(FUZZTIME) ./internal/core
	go test -run '^$$' -fuzz '^FuzzPrintable$$' -fuzztime $(FUZZTIME) ./internal/cli
	go test -run '^$$' -fuzz '^FuzzFormatJSON$$' -fuzztime $(FUZZTIME) ./internal/core/output

tools:
	@v=$$(golangci-lint version --short 2>/dev/null) || { \
		echo "golangci-lint not found: install v$(GOLANGCI_LINT_VERSION), see CONTRIBUTING.md"; exit 1; }; \
	if [ "$$v" != "$(GOLANGCI_LINT_VERSION)" ]; then \
		echo "golangci-lint $$v found, the gate wants $(GOLANGCI_LINT_VERSION)"; exit 1; \
	fi

clean:
	rm -f $(BINARY) coverage.out
	rm -rf bin dist
