# vegtam

[![check](https://github.com/vidforull/vegtam/actions/workflows/check.yml/badge.svg)](https://github.com/vidforull/vegtam/actions/workflows/check.yml)

Run `.http` files from a terminal, a CI job, or an AI agent — without leaking secrets.

- Plain `.http` files, as JetBrains' HTTP Client and VS Code REST Client write them (a subset). No account, no cloud, no telemetry.
- Secrets are masked everywhere: output, errors, JSON, history.
- Agents get a contract: one JSON document per command, exit codes, `--confirm` before anything that changes state, and a network policy you control.

## Quick start

With Go 1.27 or newer:

```sh
go install github.com/vidforull/vegtam/cmd/vegtam@latest
printf 'GET https://httpbin.org/get\n' > api.http
vegtam run api.http
```

vegtam prints the status, the time and the body, with JSON indented.
Piped or with `--json`, it prints JSON for a program instead, and
reaches localhost and private networks only as
[the policy](#scripts-and-agents) allows. On a terminal, `vegtam` alone
opens the terminal interface on the `.http` files below the current
directory.

`go install` puts `vegtam` in `$(go env GOPATH)/bin`. In a clone,
`make build` builds `./vegtam`. Releases are `tar.gz` archives for
macOS and Linux and `.deb` and `.rpm` packages for Linux (amd64,
arm64), with `checksums.txt` signed with cosign;
[docs/RELEASE.md](docs/RELEASE.md#verifying-a-download) says how to
verify one.

## What it does

### Requests, environments, checks

`api.http`, with vegtam's directives in comments that other clients skip:

```http
### Sign in
# @name login
# @capture token = $.token
POST {{host}}/login
Content-Type: application/json

{"user": "ada", "password": "{{password}}"}

### Who am I
# @name me
# @assert jsonpath $.name == "Ada"
GET {{host}}/me
Authorization: Bearer {{token}}
```

Beside it, `http-client.env.json` holds
`{"dev": {"host": "http://127.0.0.1:8080"}}`. The private file,
`http-client.private.env.json`, is kept out of version control and
holds `{"dev": {"password": "correct-horse-battery-staple"}}`, with
`$allow` to say where the password may go ([Secrets](#secrets)):

```console
$ vegtam run api.http -e dev
### api.http#login
HTTP/1.1 200 OK (3ms)

{
  "token": "***"
}

captured: token

### api.http#me
HTTP/1.1 200 OK (614µs)

{
  "id": 1,
  "name": "Ada"
}

✓ jsonpath $.name == "Ada"
```

`me` sends the token that `login` captured, and the output shows it as
`***`. `vegtam list` lists the requests, and `vegtam show` prints one
as it would be sent. `run --dry-run` resolves them without sending, and
`run --fail` exits with 4 on a status of 400 or more.
`vegtam import postman` turns a Postman export into `.http` files.

### Secrets

Secrets are the values of `http-client.private.env.json`,
`{{$env NAME}}` and `{{$cmd NAME}}`, and captures not marked `plain`.
Wherever a request is shown, a secret is its placeholder, such as
`{{password}}`. Everywhere else it is `***`, even URL-, JSON- or
base64-encoded. Masking goes by value, so a secret that comes back
hashed or in another letter case is not recognised
([docs/AUTOMATION.md](docs/AUTOMATION.md#secrets)).

A secret goes only where it belongs: a value of the private file to
the origins its `$allow` names, `{{$env NAME}}` and `{{$cmd NAME}}` to
those of the operator's policy, and a capture back to the origin of its
response. A request that would send it elsewhere, as a cloned `.http`
file or a link in a response might, is not sent, and a secret bound to
no origin goes nowhere
([docs/FORMAT.md](docs/FORMAT.md#where-secrets-may-go)). The private
file of the example above:

```json
{"dev": {"password": "correct-horse-battery-staple",
         "$allow": {"password": ["http://127.0.0.1:8080"]}}}
```

`{{$cmd NAME}}` runs a command from `http-client.cmd.json`, such as
`pass show dev/api-token`, once a person has read the file and run
`vegtam trust`. A redirect to another origin drops every header that
holds a secret.

### Scripts and agents

vegtam treats a run as a program's when stdin or stdout is not a
terminal, or with `--json`. Each command then prints one JSON document,
which `vegtam schema` describes, and exits with 0 to 6 or 130. A
program's request with a method other than GET, HEAD or OPTIONS is sent
only with `--confirm`, and so is any request with `# @note`. Only the
operator's policy can let a program reach loopback and private
addresses, or use `--insecure`, proxies, `--resolve`, `--connect-to`
and unix sockets. `vegtam describe --json` tells a program all of this.

The dev server above is on loopback, so the operator allows it in the
policy. A dry run says what to ask a person about, and `--confirm`
passes on the answer:

```console
$ cat ~/.config/vegtam/policy.json
{"network": {"allow": ["127.0.0.1:8080"]}}
$ vegtam run api.http -e dev --dry-run | jq -c '.results[] | [.ref, .confirm.reason]'
["api.http#login","method"]
["api.http#me",null]
$ vegtam run api.http -e dev --confirm=api.http#login | jq -c '.results[] | [.ref, .response.status]'
["api.http#login",200]
["api.http#me",200]
```

Without the policy, the run ends with exit code 6 before anything is
sent. The program should then ask a person, not write the policy:

```console
$ vegtam run api.http#login -e dev --confirm=api.http#login > /dev/null; echo $?
vegtam: api.http:4: Post "http://127.0.0.1:8080/login": address 127.0.0.1:8080 is private (loopback), and no person is at a terminal; allow it in policy: network.allow
6
```

The policy binds an agent when you set its environment and give it no
terminal. With a shell of its own, it can run vegtam as a person would
([docs/AUTOMATION.md](docs/AUTOMATION.md#the-operators-policy)).
[docs/AUTOMATION.md](docs/AUTOMATION.md) is the whole contract.

### Terminal interface

The terminal interface shows the requests, the selected one as it
would be sent, and the latest response. Open it with `vegtam` on a
terminal, or with `vegtam tui api.http -e dev`. Here is the test
collection `testdata/tui` in a terminal of 100 columns and 28 rows,
after `Enter` on `echo`:

```
╭──────────────────────────╮╭──────────────────────────────────────────────────────────────────────╮
│Requests                  ││Request api.http#echo                                                 │
│api.http                  ││# @assert status == 200                                               │
│  GET echo                ││GET http://127.0.0.1:8081/echo?key={{token}}&env={{$env VEGTAM_TEST_KE│
│  POST create             ││Y}}                                                                   │
│  GET escapes             ││Authorization: Bearer {{token}}                                       │
│  GET binary              ││                                                                      │
│  GET big                 ││                                                                      │
│  GET refused             ││                                                                      │
│  GET slow                │╰──────────────────────────────────────────────────────────────────────╯
│  POST login              │╭──────────────────────────────────────────────────────────────────────╮
│  GET me                  ││Response api.http#echo                                                │
│  PUT everywhere          ││HTTP/1.1 200 OK (407µs)                                               │
│broken.http ✗             ││Content-Length: 239                                                   │
│                          ││Content-Type: application/json                                        │
│                          ││Date: Tue, 20 Oct 2026 19:12:18 GMT                                   │
│                          ││X-Echo: key=***&env=***                                               │
│                          ││* connected to 127.0.0.1:8081 · connect 185µs ttfb 389µs total 405µs  │
│                          ││                                                                      │
│                          ││{                                                                     │
│                          ││  "echo": {                                                           │
│                          ││    "authorization": "Bearer ***",                                    │
│                          ││    "key": "***",                                                     │
│                          ││    "query": "key=***\u0026env=***"                                   │
│                          ││  },                                                                  │
│                          ││  "php": {                                                            │
╰──────────────────────────╯╰──────────────────────────────────────────────────────────────────────╯
 env: test                                 enter send • / search • y curl • e env • ? help • q quit
```

`Enter` sends the selected request. A method other than GET, HEAD or
OPTIONS, or a request with a note, needs a second `Enter`. `/`
searches, `e` chooses the environment, and `h` lists the latest runs.
`y` copies the request as a curl command, with secrets as shell
variables. [docs/TUI.md](docs/TUI.md) has every key.

## What's in 0.1

- `.http` and environment files in JetBrains' format, a subset ([docs/FORMAT.md](docs/FORMAT.md)).
- Checks and chains: `@assert`, `@capture`, and `@note` for a request that needs a second look.
- Secrets from private files, environment variables and trusted commands, masked by value and sent only to the origins they are bound to.
- A terminal interface, a history of runs, and import from Postman.
- Transport: CAs and PEM client certificates per host, HTTP/2, time limits, cookies, proxies, curl's `--resolve` and `--connect-to`, unix sockets, and `--verbose` ([docs/TRANSPORT.md](docs/TRANSPORT.md)).
- For programs: JSON with a schema, exit codes, `describe`, `--confirm`, and the operator's policy.
- Reproducible release builds: the same commit, Go and GoReleaser give the same bytes ([docs/RELEASE.md](docs/RELEASE.md)).

**Platforms:** Linux tested; macOS builds,
[checks pending](docs/RELEASE.md#versions); Windows builds from
source, untested.

The JSON output and the exit codes are kept stable
([docs/AUTOMATION.md](docs/AUTOMATION.md#stability)), while flags and
text output may still change.

## Not yet

Planned: retries, OAuth2, PKCS#12 client certificates, `br` and `zstd`
compression, Digest authentication, and then GraphQL, gRPC and
WebSocket. HTTP/3 is not supported.

## How it compares

Five tools close to vegtam, as their documentation stood in October
2026. A blank cell was not checked.

| | Requests | Secrets in the output | For programs | Interface |
|---|---|---|---|---|
| **vegtam** | `.http`, JetBrains' format (a subset), with its environment files | masked by value: bodies, headers, errors, `--verbose`, JSON; kept out of the history | one JSON document per command, with a schema; exit codes 0–6 and 130; `describe`; `--confirm` without a person | CLI, terminal interface |
| [Hurl](https://github.com/Orange-OpenSource/hurl) 8.0.1, 2026-04-28 | `.hurl`, a format of its own | `--secret` values are redacted from logs and reports | `--json`; documented exit codes 0–4 | CLI |
| [httpYac](https://github.com/AnWeber/httpyac) 6.16.7, 2025-03-30 | `.http` and `.rest`, compatible with JetBrains' client and REST Client | | `--json`, `--junit` | CLI, VS Code extension |
| [Bruno](https://github.com/usebruno/bruno) 4.2.1, 2026-09-30 | `.bru` or YAML (OpenCollection) | | `bru run`: JSON, JUnit or HTML reports, written to a file; exit codes 0–9 and 255 | desktop app, CLI |
| [Posting](https://github.com/darrenburns/posting) 2.11.2, 2026-10-05; 3.0 beta, 2026-10-15 | YAML, a file per request | | in the 3.0 beta, `posting run --json`, exit codes 0–2; `posting remote`, which lets an agent send through a window a person has open | terminal interface |
| [resterm](https://github.com/unkn0wn-root/resterm) 1.16.0, 2026-10-18 | `.http` and `.rest`, with directives in comments | | `resterm run`: text, JSON or JUnit | terminal interface |

Between them, the others have features that vegtam lacks yet, such as
GraphQL, gRPC, WebSocket, scripts, OAuth2, retries and HTTP/3. vegtam
is built for the run without a person. It has a network policy the
operator sets, `--confirm` for a program's requests other than GET,
HEAD or OPTIONS, and secrets masked by value.

## Documentation

- [docs/FORMAT.md](docs/FORMAT.md): the `.http` subset, directives, environments, secrets, Postman.
- [docs/AUTOMATION.md](docs/AUTOMATION.md): the contract for scripts and agents.
- [docs/TRANSPORT.md](docs/TRANSPORT.md): TLS, proxies, routes, time limits, the policy file, diagnostics.
- [docs/TUI.md](docs/TUI.md): the terminal interface and its keys.
- [docs/RELEASE.md](docs/RELEASE.md): how a release is built and checked.
- [docs/DECISIONS.md](docs/DECISIONS.md): design decisions and why.
- [CONTRIBUTING.md](CONTRIBUTING.md): the gate, `make check`, and commit messages.

## How it is built

vegtam is developed with coding agents, under the rules it gives them.
Every change passes the gate before it is merged: golangci-lint, tests
under the race detector, fuzzing, and a fixed count of suppressions
(`make check`). Each pull request is reviewed twice, then read and
merged by a person. The reasons behind the design are in
[docs/DECISIONS.md](docs/DECISIONS.md). The repository is the product's
own test bed: an agent working on vegtam runs vegtam under its policy.

## License

Developed by Vidforull.
[github.com/vidforull](https://github.com/vidforull)

MIT License: see [LICENSE](LICENSE).
