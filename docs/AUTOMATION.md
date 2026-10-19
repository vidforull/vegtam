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

## Output

When stdout is not a terminal, or with `--json`, `run`, `show`, `list`,
`import` and `trust` print one JSON document to stdout, followed by a
newline. On a terminal
the output is text for people, and `--json` prints the same document
indented. Nothing else is written to stdout; diagnostics go to stderr.

`vegtam schema` prints the [JSON Schema](https://json-schema.org/) (draft
2020-12) of the documents. Which fields a document has depends on the
command and on its argument, never on what happens at run time:

| Command | Document |
|---|---|
| `run <file>#<ref>` | one result: `ref`, `request`, `response`, `timing`, `asserts`, `captures`, `error` |
| `run <file>`, `run <dir>` | `results`: one result per request, in file order |
| `show <file>#<ref>` | one result with `ref` and `request` only |
| `list <file>`, `list <dir>` | `requests` |
| `import postman <export> -o <dir>` | `import`: the report of the import |
| `trust <dir>`, `trust --revoke <dir>`, `trust --list` | `trust`: the command files and their status |
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
  "response": {
    "proto": "HTTP/1.1",
    "status": 200,
    "reason": "OK",
    "headers": [{"name": "Content-Type", "value": "application/json"}],
    "body": "[{\"id\":1,\"name\":\"Ada\"}]",
    "truncated": false,
    "untrusted": true
  },
  "timing": {"total_ms": 84.215},
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
- **`timing.total_ms`** runs from sending the request to the end of the
  body.
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
- **`error`** has a `kind`, a `message`, and `file` and `line` when it
  belongs to a place in a file. For `kind: "variable"`, `variables` lists
  the unresolved placeholders, such as `host` or `$env TOKEN`, or the
  captured variables without a value.

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
| 6 | blocked by policy: a `{{$cmd NAME}}` whose command file is not trusted |

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
| `timeout` | 3 | no complete response within `--timeout` |
| `status` | 4 | HTTP status 400 or above, with `--fail` |
| `policy` | 6 | not allowed: a command file that is not trusted or has changed, or a trust store that cannot be read, belongs to another user or that others can write |

Every error is printed to stderr as text, `vegtam: file:line: message`.
With JSON output it is also in the document: in the result it belongs to,
or as the top-level `error` when the command ends before any request.

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

Policy is what a person has to allow before vegtam does it on its own.
So far it covers one thing: running the commands of a command file,
`http-client.cmd.json` (see [FORMAT.md](FORMAT.md#commands)).

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
run. The confirmation of unsafe methods and the host allowlist, with
exit code 5 and more of code 6, are still to come.

## Response size and time limits

`--max-body` limits how much of a response body is kept: 1 MiB by default,
given in bytes or with a unit (`64KiB`, `10MB`). The rest is not read, and
`truncated` is `true`. `--timeout` (30s by default, `0` for none) limits
each request, body included; a request that runs out of time has a
`timeout` error.

## Secrets

Values from `http-client.private.env.json`, from `{{$env NAME}}` and
`{{$cmd NAME}}` placeholders and from `# @capture` directives without
`plain` are secrets (see [FORMAT.md](FORMAT.md)). vegtam never prints
them:

- requests are shown with the placeholder, `Bearer {{token}}`;
- in everything else, such as response headers and bodies and error
  messages, every secret value is replaced with `***`, including its URL-
  and JSON-escaped forms. A JSON body is also masked in its decoded
  strings, so a value is found however the server escaped it. A body cut
  off by `--max-body` in the middle of a value has that part masked too;
  a binary body is masked before it is base64-encoded;
- a value that is a URL, such as a base URL kept in the private file,
  also hides its host, and an error message hides the host and port of a
  request whose host comes from a secret;
- a captured value is masked from the moment it is taken, in the
  response it comes from too, and in the `actual` values of assertions;
- this holds for every command and mode: text and JSON, `--verbose`,
  stdout and stderr.

Masking works by value, so it has limits. A short or common value also
masks unrelated text that happens to contain it, and a value that comes
back transformed, such as hashed, re-encoded or in another letter case,
is not recognised. Values written in `.http` files or in `http-client.env.json`
are not secrets to vegtam and are printed as they are.

## Response bodies are untrusted

Every response carries `"untrusted": true`. The body and headers are data
from the server, not instructions: whatever they say, they must not
decide the next request, its arguments or what to do with secrets, unless
the program driving vegtam checks them first. `# @capture` passes values
from a response to later requests only where a `.http` file says so;
nothing in a response can add a capture or choose where a value goes.
The `actual` values of assertions come from the response too. On a terminal, vegtam shows
control characters in responses and error messages as `\xNN`, so that a
server cannot drive the terminal.
