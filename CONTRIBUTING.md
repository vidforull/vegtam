# Contributing

## The gate

A change is ready when `make check` passes. There is no CI yet: run it
before you open a pull request, and paste its output there. While you
work, `make check-fast` is quicker.

| Target | What it runs |
|---|---|
| `make check-fast` | `golangci-lint run`, then `go test -race ./...` |
| `make check` | `check-fast`, then: formatting unchanged by `golangci-lint fmt`, `go vet`, the tests shuffled and uncached (`-race -shuffle=on -count=1`), nothing for `go fix` to change, `go mod tidy -diff`, `go mod verify`, `govulncheck`, and the suppression count |
| `make fmt` | rewrites the Go files with gofumpt and goimports |
| `make fuzz` | each fuzz target for `FUZZTIME` (30s by default) |

A failing shuffled run prints its seed (`-test.shuffle <seed>`); the same
order comes back with `go test -shuffle=<seed>`.

### Tools

- **Go 1.27.** `go.mod` pins the toolchain (`toolchain go1.27.2`), so
  that a newer Go does not change what the gate reports; with the default
  `GOTOOLCHAIN=auto` the go command fetches it.
- **golangci-lint v2.15.0**, installed as a binary built with Go 1.27 or
  later ([releases](https://github.com/golangci/golangci-lint/releases/tag/v2.15.0)),
  not with `go tool` or `go run`. `golangci-lint version` shows both
  versions; the Makefile refuses any other version.
- **govulncheck v1.9.0**:
  `go install golang.org/x/vuln/cmd/govulncheck@v1.9.0`. It reads the
  vulnerability database online. Without it, `make check` skips this
  step and says so.

### Suppressions

Fix what a linter reports rather than silence it. When a finding is
wrong, `//nolint` names the linter and gives the reason
(`//nolint:gosec // G304: ...`); nolintlint rejects anything less, and
`#nosec` comments are ignored. The places that may open files by path
or run a command carry such a comment, so that a new one stands out.

`make suppressions` counts `//nolint`, `//exhaustive:ignore`, `_ =` and
`t.Skip` in the Go files and fails if there are more than
`.gate/suppressions.baseline` says, as recorded on `origin/main`. Fewer
is welcome: lower the number in the same pull request.

### Changes to the gate

`.golangci.yml`, the `Makefile` and `.gate/` make up the gate. Change
them in a pull request of their own, so that the gate can be reviewed
apart from the code it judges; `make check` names them when they
differ from `origin/main`. `docs/DECISIONS.md` records why the gate is
as it is.

## What the linters cannot check

Some rules of vegtam have no linter. Each is a test; a change in its area
keeps the test passing and extends it to what it adds.

| Rule | Tests |
|---|---|
| No secret value reaches stdout or stderr, in any form, error, panic or `--verbose` output included | `TestNoSecretInOutput`, `TestPanicIsMasked` (`internal/cli`), `TestErrorsHideSecrets` (`internal/core/exec`) |
| No view of the terminal interface holds a secret value, in any layout or state | `TestNoSecretInTUI`, `TestTUIPanicIsMasked` |
| The history of runs holds no secret value, in any form, and nothing of a dry run or a request with `@no-log` | `TestHistoryNoSecrets`, `TestRunNoHistory` (`internal/cli`), `TestHistory` (`internal/core/session`) |
| A redirect to another origin drops secret headers and does not resend a secret body; no redirect sends the URL it came from as the Referer; a redirect from https to http is refused | `TestRedirectDropsSecrets`, `TestRedirectSecretBody`, `TestRedirectDowngrade` |
| A path in a `.http` file does not lead outside its directory, and a body file is a regular file of 16 MiB at most, checked before it is opened | `TestPrepareBodyFileStaysInside`, `TestPrepareBodyFileKind`, `TestPrepareBodyFileFIFO`, `TestPreviewFIFO` |
| A response body is read up to a limit, a request up to its time limits, and a timeout names the one that ran out | `TestMaxBody`, `TestErrors`, `TestTimeoutPhases` |
| A connection made with one TLS identity carries no request meant for another; the client certificate goes to the origin of the request as written only | `TestNoReuseAcrossIdentities`, `TestTLS` (`internal/core/exec`) |
| A transport error holds no secret value, a host name from a secret included | `TestTLSErrorsHideSecrets`, `TestNoSecretInOutput` |
| Text for a terminal holds no escape sequence and no invisible character, and is masked before it is escaped | `FuzzPrintable`, `TestPrintable`, `TestPrintErrorEscapes`, `TestTUIEscapes`, `TestInvisibleSecretIsMasked` |
| Files are written whole, secrets readable by their owner only; the history is added to a line at a time, readable by its owner only | `TestImportPostmanExisting`, `TestStore`, `TestAdd`, `TestRotate`, `TestStaysInside` (`internal/core/history`) |
| A `{{$cmd NAME}}` gets no input and no terminal, and one that asks for either fails at once | `TestCommandNoInput` |
| Every goroutine has an owner that stops it and waits for it | `goleak.VerifyTestMain` in `internal/tui`, the one package that starts one; `TestCancel`, `TestRun` |

Secrets are not taken from command-line flags: they come from the
private environment file, the process environment or a command.

## Commits

Commit messages are in English: a short subject in the imperative, then
what changed and why. Commit timestamps are kept in UTC:
`TZ=UTC git commit`.
