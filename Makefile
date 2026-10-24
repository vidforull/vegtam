# Commits in this repository carry UTC timestamps. Commit with:
#
#   TZ=UTC git commit
#
# Override the version with: make build VERSION=0.1.0. The commit and its
# date, in UTC, are stamped as well: the same commit builds the same
# binary, as with goreleaser (docs/RELEASE.md).
#
# The gate: `make check-fast` while working, `make check` before every pull
# request. CONTRIBUTING.md says what each step is for and how to install
# the tools at these versions.

BINARY  := vegtam
VERSION ?= $(patsubst v%,%,$(shell git describe --tags --always --dirty 2>/dev/null || echo dev))
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE    ?= $(shell TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
LDFLAGS  = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

GOLANGCI_LINT_VERSION := 2.15.0
GOVULNCHECK_VERSION   := v1.9.0
GORELEASER_VERSION    := 2.18.3
FUZZTIME              ?= 30s

# Suppressions: //nolint, //exhaustive:ignore, `_ =` and t.Skip in Go files.
BASELINE     := .gate/suppressions.baseline
SUPPRESSIONS := //nolint|//exhaustive:ignore|^[[:space:]]*_(, _)* = |\bt\.Skip
# The files of the gate, which a pull request changes only on its own.
GATE_FILES   := .golangci.yml Makefile .gate .github

.PHONY: build test vet fmt lint check-fast check release-check suppressions gate-files vuln fuzz tools clean

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

# What a release needs before its tag: the gate, then goreleaser check of
# .goreleaser.yaml. Without goreleaser, or before there is a
# .goreleaser.yaml, that step is skipped, and says so.
release-check: check
	@if ! command -v goreleaser >/dev/null 2>&1; then \
		echo "SKIPPED goreleaser check: not installed (go install github.com/goreleaser/goreleaser/v2@v$(GORELEASER_VERSION))"; \
	elif [ ! -f .goreleaser.yaml ]; then \
		echo "SKIPPED goreleaser check: no .goreleaser.yaml"; \
	else \
		v=$$(goreleaser --version 2>/dev/null | sed -n 's/^GitVersion: *v\{0,1\}//p'); \
		if [ "$$v" != "$(GORELEASER_VERSION)" ]; then \
			echo "goreleaser $$v found, the gate wants $(GORELEASER_VERSION)"; exit 1; \
		fi; \
		echo "goreleaser check"; goreleaser check; \
	fi

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
	go test -run '^$$' -fuzz '^FuzzParsePolicy$$' -fuzztime $(FUZZTIME) ./internal/core/policy
	go test -run '^$$' -fuzz '^FuzzEnvFile$$' -fuzztime $(FUZZTIME) ./internal/core/env
	go test -run '^$$' -fuzz '^FuzzParseOrigin$$' -fuzztime $(FUZZTIME) ./internal/core
	go test -run '^$$' -fuzz '^FuzzJSON$$' -fuzztime $(FUZZTIME) ./internal/core/redact

tools:
	@v=$$(golangci-lint version --short 2>/dev/null) || { \
		echo "golangci-lint not found: install v$(GOLANGCI_LINT_VERSION), see CONTRIBUTING.md"; exit 1; }; \
	if [ "$$v" != "$(GOLANGCI_LINT_VERSION)" ]; then \
		echo "golangci-lint $$v found, the gate wants $(GOLANGCI_LINT_VERSION)"; exit 1; \
	fi

clean:
	rm -f $(BINARY) coverage.out
	rm -rf bin dist
