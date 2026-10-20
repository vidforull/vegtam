# Automation: driving vegtam from scripts and agents

vegtam is meant to be run by programs as much as by people: shell scripts,
CI jobs and AI agents. What they can rely on is the JSON output, its
schema, the exit codes and the way secrets are kept out of both. This
document describes that contract.

```sh
vegtam list api/                          # what is there to run
vegtam show api/users.http#list -e dev    # what a request would send
vegtam run api/users.http#list -e dev     # send it
vegtam run api/ -e dev --fail             # send everything, fail on HTTP errors
```

## The terminal interface is for people

`vegtam` with no command opens the terminal interface (`vegtam tui`) only
when stdin and stdout are both terminals. Otherwise, as when a script or
an agent runs it, it prints the help on stderr and exits with 2, a usage
error, with the error document on stdout as for any other; it never
waits for keys. `vegtam tui` itself refuses to start without a terminal,
with the same exit code. Everything the interface does, `run`, `show`
and `list` do with output a program can read.

## Output

When stdout is not a terminal, or with `--json`, `run`, `show`, `list`,
`import`, `trust` and `policy` print one JSON document to stdout,
followed by a newline. On a terminal
the output is text for people, and `--json` prints the same document
indented. Nothing else is written to stdout; diagnostics go to stderr.

`vegtam schema` prints the [JSON Schema](https://json-schema.org/) (draft
2020-12) of the documents. Which fields a document has depends on the
command and on its argument, never on what happens at run time:

| Command | Document |
|---|---|
| `run <file>#<ref>` | one result: `ref`, `request`, `transport`, `response`, `timing`, `remote_addr`, `resolved_by`, `proxy`, `tls`, `redirects`, `cookies`, `asserts`, `captures`, `warnings`, `error` |
| `run <file>`, `run <dir>` | `results`: one result per request, in file order |
| `show <file>#<ref>` | one result with `ref`, `request`, `transport` and `warnings` only |
| `list <file>`, `list <dir>` | `requests` |
| `import postman <export> -o <dir>` | `import`: the report of the import |
| `trust <dir>`, `trust --revoke <dir>`, `trust --list` | `trust`: the command files and their status |
| `policy` | `policy`: the operator's policy and what applies to a run |
| an error that ends a command before any request | `error` only |

A result for `run api/users.http#list -e dev` looks like this (shortened):

```json
{
  "schema_version": 1,
  "ref": "api/users.http#list",
  "request": {
    "method": "GET",
    "url": "https://api.example.test/users?limit=2",
    "headers": [{"name": "Authorization", "value": "Bearer {{token}}"}]
  },
  "transport": {"connect_timeout_ms": 10000, "read_timeout_ms": 30000, "max_time_ms": 120000},
  "response": {
    "proto": "HTTP/1.1",
    "status": 200,
    "reason": "OK",
    "headers": [{"name": "Content-Type", "value": "application/json"}],
    "body": "[{\"id\":1,\"name\":\"Ada\"}]",
    "truncated": false,
    "untrusted": true,
    "tls_verified": true
  },
  "timing": {"total_ms": 84.215, "name_lookup_ms": 1.902, "connect_ms": 12.318, "app_connect_ms": 31.04, "start_transfer_ms": 83.77, "reused": false},
  "remote_addr": "192.0.2.10:443",
  "tls": {
    "version": "TLS 1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "alpn": "http/1.1",
    "verified": true,
    "peer": {"subject": "CN=api.example.test", "issuer": "CN=Example CA,O=Example", "not_after": "2027-01-31T23:59:59Z"}
  },
  "cookies": {
    "sent": [{"hop": 0, "name": "session", "domain": "api.example.test", "path": "/", "host_only": true, "secure": true, "http_only": true}]
  },
  "asserts": [
    {"expression": "status == 200", "passed": true, "actual": "200"},
    {"expression": "jsonpath $[0].name == \"Grace\"", "passed": false, "actual": "\"Ada\""}
  ],
  "error": {
    "kind": "assert",
    "message": "assertion failed: jsonpath $[0].name == \"Grace\"",
    "file": "api/users.http",
    "line": 4
  }
}
```

- **`ref`** names the request as `file#name`, or `file#N` (counting from
  1) when it has no `# @name`. It can be passed back to `run` and `show`.
  For a file that does not parse, it is the file alone.
- **`request`** is the request as it went, or would go, on the wire.
  Secrets appear as their placeholders. It is absent if the request could
  not be resolved.
- **`response`** is absent when no response came, after an error before
  or while sending, and with `--dry-run`; errors of kind `assert`,
  `capture` and `status` come with the response. Headers are a list of
  name and value pairs, sorted by name; a name may repeat. The body is a
  string: the text as received, or base64 with `"encoding": "base64"` if
  it is not valid UTF-8.
  `tls_verified` is `true` when every hop of the request, redirects
  included, went over TLS with the server's certificate checked, `false`
  if one went over plain `http`, and with `--insecure`: only when it is
  `true` could nothing on the way have read or changed the exchange. `proto` is the version spoken, `HTTP/2.0` for
  HTTP/2.
- **`transport`** is what the request was, or would be, sent with: the
  `version` asked for by a flag or the request line (absent if none),
  and the limits in milliseconds, `0` for none: `connect_timeout_ms`,
  `read_timeout_ms` and `max_time_ms`, each the flag's or lower, if the
  request's directive says so.
- **`timing`** says how long the request took, in milliseconds.
  `total_ms` runs from sending the request to the end of the body, or to
  the error. The phases have the names of curl's `-w` and of Hurl's
  report, each running from the start of the request to the end of its
  phase: `name_lookup_ms` (DNS), `connect_ms` (TCP, to the proxy if there
  is one), `app_connect_ms` (the TLS handshake) and `start_transfer_ms`
  (the first byte of the response). A phase that did not happen is
  absent: the lookup of an IP address, TLS over `http`, and all three on
  a connection used before. `reused` is `true` when no connection was made
  for the request: every hop went on one that an earlier request of the
  run had made, so the time has no DNS, connect or TLS in it. With
  redirects, each phase is the sum over the hops, as curl adds them up,
  and each redirect has its own `timing`.
- **`remote_addr`**, **`proxy`** and **`tls`** describe the connection of
  the last hop: the IP address and port connected to (the proxy's if
  there is one), the proxy, as `scheme://host:port` with a user and
  password shown as `***@`, and what the TLS handshake agreed on: the
  `version`, the `cipher`, the `alpn` protocol, whether the server's
  certificate was `verified`, and the `peer` certificate's `subject`,
  `issuer` and `not_after`. `remote_addr` is `***` when the host of the
  request holds a secret, since the address would tell it, and so is the
  certificate's `subject`, which names the host or its address.
  **`resolved_by`** names the flag that sent the connection elsewhere
  than its host: `--resolve`, `--connect-to`, `--unix-socket` or
  `--abstract-unix-socket`, whose `remote_addr` is the socket; it is
  absent when the host was looked up as usual, or a proxy took it.
- **`redirects`** lists each redirect the request followed, and the last
  one if it was refused: the `status`, the `location` as the server wrote
  it, masked, the headers `dropped` as it left the origin of the request,
  and the `remote_addr`, `resolved_by`, `proxy` and `timing` of that hop.
- **`cookies`** names the cookies the jar of the run `sent` and those the
  responses `set`, with their `domain`, `path` and flags, and for each
  one set, whether the jar `stored` it and, if not, the `reason`. `hop`
  is 0 for the request as written and n after the n-th redirect. No
  value is ever shown (see [Cookies](#cookies)).
- These come after an error too, as far as the request got, which says
  where it stopped: a `connect` timeout with `connect_ms` and no
  `app_connect_ms` stopped in the TLS handshake; a handshake that failed
  still has `tls.peer`, the certificate that did not pass, whose issuer
  says what CA to trust. They are absent for a dry run.
- **`asserts`** has the outcome of each `# @assert` of the request, in
  order: the `expression` as written, whether it `passed`, and the
  `actual` value checked, masked like the response and cut off after 200
  bytes with `...`, or in parentheses why there is none, such as
  `(absent)`. It is absent if the request has no assertions, without a
  response, and with `--dry-run`.
- **`captures`** lists the variables the `# @capture` directives of the
  request took, for the requests after it: `name`, `source` as written,
  and `secret`. The values are never in the output. A capture that found
  no value is not listed; it is in `error`.
- **`warnings`** says what vegtam ignored and why, the request running
  all the same: a directive of another client, a limit above the flag's,
  the `SSLConfiguration` of an environment file. Each has a `message`,
  and `file` and `line` when there are any; each is also printed on
  stderr as `vegtam: file:line: warning: ...`.
- **`error`** has a `kind`, a `message`, and `file` and `line` when it
  belongs to a place in a file. For `kind: "variable"`, `variables` lists
  the unresolved placeholders, such as `host` or `$env TOKEN`, or the
  captured variables without a value. For `kind: "timeout"`,
  `timeout_phase` says which limit ran out: `connect`, `read` or
  `total`.

### Stability

`schema_version` is `1`. Fields are only ever added: none is renamed,
removed or given another meaning without a new `schema_version`. Ignore
fields you do not know. New error kinds may appear; treat an unknown kind
by its exit code.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | an assertion (`# @assert`) failed |
| 2 | bad arguments, a `.http` or environment file that does not parse, an unresolved variable, an invalid request, a capture (`# @capture`) that found no value, or an export that cannot be imported |
| 3 | network or TLS error, or timeout |
| 4 | HTTP status 400 or above, with `run --fail` |
| 5 | reserved: the request needs confirmation |
| 6 | blocked by policy: a `{{$cmd NAME}}` whose command file is not trusted, an address vegtam never connects to or that the operator's policy does not allow, or a policy file that cannot be read |
| 130 | interrupted: Ctrl-C (SIGINT) or SIGTERM stopped a request or a `{{$cmd NAME}}` |

Without `--fail`, any HTTP status is a success: the status is in the
output. With several requests, the exit code is the highest among them,
and so it is within one result: a status error with `--fail` takes the
place of a failed capture, which takes the place of failed assertions.
The outcome of every assertion is in `asserts` all the same.

## Errors

| `kind` | Exit code | Cause |
|---|---|---|
| `assert` | 1 | an `@assert` failed; the response is in the result |
| `usage` | 2 | bad arguments, a missing file, an unknown request or environment |
| `parse` | 2 | a `.http` or environment file outside the supported format |
| `variable` | 2 | a placeholder without a value |
| `request` | 2 | a resolved request that cannot be sent: URL, header, body file |
| `import` | 2 | an export that cannot be read: not a collection, not JSON, no collections in a directory |
| `capture` | 2 | an `@capture` found no value: the body is not JSON or was cut off, a path is absent or does not fit, a header is missing, the value is `null`, or an object or array for a secret capture |
| `network` | 3 | DNS, connection, TLS, redirects |
| `timeout` | 3 | a time limit ran out; `timeout_phase` says which: `connect`, `read` or `total` |
| `status` | 4 | HTTP status 400 or above, with `--fail` |
| `policy` | 6 | not allowed: a command file that is not trusted or has changed, or a trust store that cannot be read, belongs to another user or that others can write; an address that vegtam never connects to, or a loopback or private one that the operator's policy does not allow; a policy file that does not parse, or that others can write |
| `canceled` | 130 | SIGINT or SIGTERM came while a request waited for its response or a command ran; the requests after it are canceled too |

Every error is printed to stderr as text, `vegtam: file:line: message`.
With JSON output it is also in the document: in the result it belongs to,
or as the top-level `error` when the command ends before any request.

A bug that makes vegtam panic is printed to stderr only, as
`vegtam: internal error:` and a stack trace, with secret values masked
there too, and the exit code is 2, as for any Go program that panics.

When `run` covers several requests, an error stops only its own request;
the others are still sent. A file that does not parse becomes one result
with a `parse` error. `list` lists every file that parses, reports the
others on stderr, and puts the first error in `error`.

## Dry runs

`run --dry-run` does everything but send: it reads the environment files,
resolves every placeholder, reads body files and checks that each request
could be built (an `http` or `https` URL with a host, valid headers). The
output has `request` and no `response`; the exit code is 2 if any request
fails these checks, 0 otherwise. It is the way to check a collection, or
to see what a request would send before sending it.

Directives are parsed, so a malformed `@assert` or `@capture` fails the
dry run, but none is evaluated. Nothing is captured either: a variable
that an earlier request would capture stays a placeholder, `{{token}}`,
and the URL or header that holds it is left unchecked.

A dry run also runs no command: `{{$cmd NAME}}` is checked against the
trust store and the command file, and the request shows the
placeholder.

`show <file>#<ref>` prints one request as written, or with `-e` as it would
be sent; like a dry run, it runs no command.

## Importing

`import postman` converts a Postman export into `.http` and environment
files (see [FORMAT.md](FORMAT.md)) and prints a report:

- **`collections`**, **`requests`** and **`imported`**: the requests in
  the export and those written as requests. The others are written
  commented out and listed in `skipped`.
- **`environments`**: the names to pass to `-e`.
- **`files`**: every file written.
- **`skipped`**: what was not imported, or not as it was, one entry per
  occurrence: a `category` (`request`, `body`, `auth`, `script`,
  `variable`, `header`, `example`, `setting` or `file`), a `reason`, and
  `where`: `file#name` for a request; a folder's `.http` file, or its
  directory if it has no requests of its own; a collection's directory;
  the output directory for the whole export; or a file of the export.
- **`variables`**: variables the requests use that need a look, with the
  environment files to look in: `secret` for a value from the export
  that is now in the private files, `unset` for a variable without any
  value.

The exit code is 0 when the files are written, whatever was skipped.
Without `--force`, existing files make it 2 and nothing is written. Run
`run <dir> --dry-run -e <env>` next to check every request.

## Policy

Policy is what a person has to allow before vegtam does it on its own:
running the commands of a command file, `http-client.cmd.json` (see
[FORMAT.md](FORMAT.md#commands)), and what the operator's policy file
allows of the network.

### Trusted command files

- `vegtam trust <dir>` trusts the `http-client.cmd.json` in `<dir>` (or
  the file named): it records where the file is, as an absolute path
  with the symbolic links of its directory resolved, and a SHA-256 of
  the file and of the files its commands name by relative paths, such
  as `./bin/token` or `token.py`, in `$XDG_CONFIG_HOME/vegtam/trust.json`,
  or `~/.config/vegtam/trust.json` if `XDG_CONFIG_HOME` is not set.
  Programs found in `PATH` or named by absolute paths are not covered.
- The trust is for that place: a symbolic link elsewhere to a trusted
  file is not trusted. It holds for every `.http` file in the directory
  and below it, as the nearest command file is used.
- If the file or a file its commands name changes, the commands do not
  run until it is trusted again.
- The store is readable by its owner only; one that belongs to another
  user, or that others can write, directory included, trusts nothing.
- `vegtam trust --revoke <dir>` takes the trust back, also for a
  directory since deleted; `vegtam trust --list` lists the files with a
  `status`: `trusted`, `changed` or `missing`.
- A request with a `{{$cmd NAME}}` from a file that is not trusted fails
  with kind `policy` and exit code 6 before anything is sent, also with
  `--dry-run` and `show -e`, and whatever else is wrong with it.

Trusting is a decision for a person, who reads the commands first. A
program that gets a `policy` error should stop and ask, not run `vegtam
trust` itself: the error message names the command for the person to
run. The confirmation of unsafe methods, with exit code 5, is still to
come.

### The operator's policy

A program runs without a person at a terminal: stdin or stdout is not a
terminal, or `--json` is given. Such a run gets what the operator's
policy, `$XDG_CONFIG_HOME/vegtam/policy.json`, allows, and no more; a
file, a response or the program's own arguments cannot widen it.
`vegtam policy --json` prints it, with `run.unattended`, the proxies a
run goes through and the addresses never connected to; `vegtam policy
--help` describes every field.

- **Addresses.** vegtam never connects to the metadata services of
  clouds (`169.254.169.254`, `fd00:ec2::254` and the others that
  `never` lists), nor to link-local, multicast or unspecified
  addresses, whoever runs it. Without a person, it connects to loopback
  (`127.0.0.0/8`, `::1`), RFC 1918, `100.64.0.0/10` and `fc00::/7`
  addresses only as `network.allow` names them: `"localhost:3000"`,
  `"127.0.0.1"`, `"127.0.0.1:8080"`, `"10.0.0.0/8"`. The check is of the
  address each connection is made to, every hop and every connection.
  A refused one is an error of kind `policy`, before anything is sent:

  ```json
  {"kind": "policy", "message": "Get \"http://localhost:3000/health\": address 127.0.0.1:3000 is private (loopback), and no person is at a terminal; allow it in policy: network.allow"}
  ```

- **Proxy.** Without a person, requests go through `network.proxy`, a
  URL or `"environment"` for that of `HTTPS_PROXY`, `HTTP_PROXY` and
  `NO_PROXY`; with none there, through no proxy, and a warning says that
  the environment's is not used. Through a proxy, the target of each
  request is looked up here and checked as a connection would be,
  numbers such as `2852039166` read as the IPv4 addresses they are; a
  target that does not resolve here, or only to `0.0.0.0`, is refused
  unless `network.allow` names it with its port. The proxy itself is
  connected to as the proxy only: a request to its address goes direct,
  and is checked as any other. An https proxy does not carry a request
  that `--insecure` leaves unchecked: its own certificate would go
  unchecked too.
- **Unchecked certificates.** `--insecure` without a person leaves
  unchecked the hosts of `network.insecure_hosts` only, and is a
  `usage` error without them.
- **Routes and sockets.** `--proxy` without a person is a `usage` error:
  requests go through the policy's proxy. `--resolve`, `--connect-to`
  and `--unix-socket` are taken only as `network.resolve`,
  `network.connect_to` and `network.unix_sockets` list them: a route as
  the flag writes it, its host in lower case; a socket by the file its
  links lead to, which is then what is connected to. Another is a
  `usage` error that names the entry. None of them comes from a file,
  and routes do not apply to the proxy. `--noproxy` is taken: going
  direct is what the guard sees. `--proxy-auth` is not: the policy gives
  its proxy's credentials, `network.proxy_auth`, and no request may read
  the variable that holds them (`{{$env NAME}}` of it is a `policy`
  error), so that a file cannot send them elsewhere.
- **TLS by host.** `hosts` gives an origin CAs trusted for it alone and a
  client certificate offered to it alone, in every mode.
- **Limits.** `limits.*_ceiling` hold every flag and directive.

The policy is the operator's to write. A program that gets a `policy`
error for an address should stop and tell a person which entry would
allow it, from the message: it does not write the policy itself, and
it does not try another address, port or name to get past it.

The policy holds against what vegtam's arguments, files and responses
say. It is found through `XDG_CONFIG_HOME`, or `HOME`, so a program that
sets vegtam's environment can name another policy, as it can run
another client: run an agent with an environment that the operator
sets, and without a shell of its own, for the policy to bind it.
Warnings about the run itself, such as a flag above a ceiling or a
proxy of the environment that is not used, go to stderr only; the
`transport` of each result gives the limits that hold.

## Response size and time limits

`--max-body` limits how much of a response body is kept: 1 MiB by default,
given in bytes or with a unit (`64KiB`, `10MB`). The rest is not read, and
`truncated` is `true`. Three limits bound the time of each request, given
in seconds (`5`) or with a unit (`500ms`, `2m`, `1m30s`), `0` or `none` for none:

| Flag | Default | Limits |
|---|---|---|
| `--connect-timeout` | 10s | getting a connection: DNS, TCP, a proxy's CONNECT and the TLS handshake, all of it |
| `--read-timeout` | 30s | each wait for data from the server once the request is sent: the headers, then each part of the body |
| `--max-time` | 2m | the whole exchange, redirects and body included; `--timeout` is its old name |

The directives `# @connection-timeout`, `# @timeout` and `# @max-time`
may lower them for a request, never raise them. The ceilings of the
operator's policy (`limits.max_time_ceiling`, `read_timeout_ceiling`,
`connect_timeout_ceiling`) hold the flags too: a flag above one, or `0`,
is a warning, and the ceiling holds. `transport` in each result, of
`--dry-run` and `show` too, gives the limits that apply.

## Cookies

A run keeps the cookies that responses set, in memory, for the requests
after them in the same run, as `.http` files that sign in expect; each
run starts without any, so that a run does what its files say whatever
ran before. Which cookie goes where follows RFC 6265 with the public
suffix list, and RFC 6265bis's rules on `Secure`, `__Secure-` and
`__Host-` and its limits (see [FORMAT.md](FORMAT.md#cookies)). The
cookies are never written to disk. `--no-cookies` turns them off for a
run, `# @no-cookie-jar` for a request: it neither sends the cookies of
the run nor keeps those its response sets.

A cookie's value is a secret: `cookies` in the output names the cookies,
a `Set-Cookie` header shows `***` for the value, and a value of 8 bytes or
more is masked wherever else it appears.

## TLS and the HTTP version

`--cacert <file>` trusts the CA certificates of a PEM file as well as
the system's. `--cert <file>` and `--key <file>` give a PEM client
certificate and its unencrypted key, which is offered to the origin of
each request as written, not after a redirect elsewhere. `--http1.1`,
`--http2` and `--http2-prior-knowledge` set the HTTP version of every
request. None of this comes from a `.http` or environment file.

`--insecure` turns off the check of server certificates for a person at
a terminal. When stdin or stdout is not a terminal, or with `--json`, it
leaves unchecked only the hosts that the operator's policy names in
`network.insecure_hosts`, and without them it is a `usage` error, exit
code 2. A program that has to reach a server with a private CA passes
`--cacert`.

## Secrets

Values from `http-client.private.env.json`, from `{{$env NAME}}` and
`{{$cmd NAME}}` placeholders and from `# @capture` directives without
`plain` are secrets (see [FORMAT.md](FORMAT.md)). vegtam never prints
them:

- requests are shown with the placeholder, `Bearer {{token}}`;
- in everything else, such as response headers and bodies and error
  messages, every secret value is replaced with `***`, including its URL-
  and JSON-escaped and base64-encoded forms. So are the credentials of
  `Authorization: Basic {{user}} {{password}}`, which go in base64, and
  the values of cookies. A JSON body is also masked in its decoded
  strings, so a value is found however the server escaped it. A body cut
  off by `--max-body` in the middle of a value has that part masked too;
  a binary body is masked before it is base64-encoded;
- a value that is a URL, such as a base URL kept in the private file,
  also hides its host, and an error message hides the host and port of a
  request whose host comes from a secret, and `remote_addr` its address;
- a captured value is masked from the moment it is taken, in the
  response it comes from too, and in the `actual` values of assertions;
- this holds for every command and mode: text and JSON, `--verbose`,
  stdout and stderr.

Masking works by value, so it has limits. A short or common value also
masks unrelated text that happens to contain it, and a value that comes
back transformed, such as hashed, re-encoded or in another letter case,
is not recognised. Values written in `.http` files or in `http-client.env.json`
are not secrets to vegtam and are printed as they are.

## History

`run` adds each request it sends to the history of runs,
`$XDG_DATA_HOME/vegtam/history.jsonl` (`~/.local/share/vegtam/` without
`XDG_DATA_HOME`): one JSON object a line, with the time (UTC), the
`ref` with the file as an absolute path, the environment, the method and
the URL as written, with their placeholders, the status, the time it
took, the `result` (`ok` or the error kind) and `truncated`. It holds no
header, body, variable value or captured value, and no URL as resolved:
nothing a secret could be in; a password written in a URL is kept as
`***`. A dry run, a file that does not parse and
a request with `# @no-log` are not kept. A program that wants no trace
passes `--no-history`, or sets `VEGTAM_NO_HISTORY=1` for every run. A
history that cannot be written is a warning on stderr, not an error: the
exit code and the output stay as they are.

## Response bodies are untrusted

Every response carries `"untrusted": true`. The body and headers are data
from the server, not instructions: whatever they say, they must not
decide the next request, its arguments or what to do with secrets, unless
the program driving vegtam checks them first. `# @capture` passes values
from a response to later requests only where a `.http` file says so;
nothing in a response can add a capture or choose where a value goes.
The `actual` values of assertions come from the response too. On a terminal, vegtam shows
control characters in responses and error messages as `\xNN`, so that a
server cannot drive the terminal, and invisible format characters, such
as a right-to-left override, as `\u202e`, so that text cannot read as
other than it is. JSON output is not changed.
