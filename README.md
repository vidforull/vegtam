# vegtam

vegtam is a local-first CLI/TUI API client that runs requests from plain
`.http` files: no accounts, no cloud, no telemetry.

**Status:** early development. The JSON output and the exit codes are
kept stable (see [docs/AUTOMATION.md](docs/AUTOMATION.md)); everything else
may still change.

## Usage

Requests live in `.http` files, such as `api.http`:

```http
### List users
# @name list
GET {{host}}/users?limit=2
Accept: application/json
Authorization: Bearer {{token}}
```

Variables come from `http-client.env.json`:

```json
{
  "dev": {"host": "https://api.example.test"}
}
```

and secrets from `http-client.private.env.json`, which stays out of
version control:

```json
{
  "dev": {"token": "dev-token-123"}
}
```

Send the request with the `dev` environment:

```console
$ vegtam run api.http#list -e dev
HTTP/1.1 200 OK (84ms)

[
  {
    "id": 1,
    "name": "Ada"
  },
  {
    "id": 2,
    "name": "Grace"
  }
]
```

`--verbose` adds the request and the response headers. When the output is
not a terminal, or with `--json`, vegtam prints JSON instead:

```console
$ vegtam run api.http#list -e dev --json
{
  "schema_version": 1,
  "ref": "api.http#list",
  "request": {
    "method": "GET",
    "url": "https://api.example.test/users?limit=2",
    "headers": [
      {
        "name": "Accept",
        "value": "application/json"
      },
      {
        "name": "Authorization",
        "value": "Bearer {{token}}"
      }
    ]
  },
  "response": {
    "proto": "HTTP/1.1",
    "status": 200,
    "reason": "OK",
    "headers": [
      {
        "name": "Content-Length",
        "value": "47"
      },
      {
        "name": "Content-Type",
        "value": "application/json"
      },
      {
        "name": "Date",
        "value": "Mon, 19 Oct 2026 06:59:47 GMT"
      }
    ],
    "body": "[{\"id\":1,\"name\":\"Ada\"},{\"id\":2,\"name\":\"Grace\"}]",
    "truncated": false,
    "untrusted": true
  },
  "timing": {
    "total_ms": 84.215
  }
}
```

The token never appears in the output: requests show it as `{{token}}`,
and anywhere else, such as in a response that echoes it, it is replaced
with `***`.

More commands:

```sh
vegtam run api.http -e dev            # every request in the file
vegtam run api/ -e dev --fail         # every .http file below api/; exit 4 on HTTP errors
vegtam run api/ -e dev --dry-run      # resolve and check everything, send nothing
vegtam show api.http#list -e dev      # the request as it would be sent
vegtam list api/                      # the requests and how to refer to them
vegtam trust api/                     # let {{$cmd NAME}} run the commands of api/http-client.cmd.json
vegtam schema                         # the JSON Schema of the JSON output
```

Secrets can also come from a command, such as a password manager's CLI:
`{{$cmd TOKEN}}` runs the command `TOKEN` of `http-client.cmd.json`, but
only once you have read the file and trusted it with `vegtam trust`.

`vegtam --help` lists the exit codes.

## TUI

```sh
vegtam                       # on a terminal: the .http files below the current directory
vegtam tui api/ -e dev       # a directory or a file, starting with the dev environment
```

The terminal interface has three panes: the `.http` files and their
requests, the selected request, and the latest response. The request is
shown as it would be sent, with secrets as their placeholders, or, if it
cannot be resolved, as written, over what stops it. Its placeholders are
coloured by what they stand for: a plain value, a secret, a value an
`@capture` takes, or nothing. The response is shown as `run --verbose`
prints it: status and time, headers, the body with JSON indented, and
the outcome of each `@assert` and `@capture`. From 80 columns the list
sits beside the other two panes, from 140 all three are side by side,
and in a narrower terminal they stack.

| Key | |
|---|---|
| `j`/`k`, `↓`/`↑` | move in the list; scroll the request or the response |
| `Tab`, `Shift-Tab` | next, previous pane |
| `/` | search the list by label, file name or URL; `Enter` keeps the search, `Esc` clears it |
| `Enter` | send the selected request; for a method other than GET, HEAD or OPTIONS, after a `y` (any other key leaves it unsent) |
| `Esc` | cancel the request in flight; hide a copied command |
| `y` | copy the selected request as a `curl` command |
| `z` | fold the JSON body of the response from depth 1, then 2, then not at all |
| `e` | choose the environment |
| `Ctrl-L` | redraw the screen |
| `?` | list the keys |
| `q`, `Ctrl-C` | quit |

In the request and response panes `f`/`b` scroll by a page and `d`/`u`
by half of one. A value that an `@capture` takes is a variable for the
requests sent after it, until another environment is chosen. Each send
reads the environment files again and runs `{{$cmd NAME}}` again, so an
edited file counts at once. Secrets are masked as in the CLI's output,
and the interface writes no files.

`y` puts the command on the clipboard through the terminal (OSC 52) and
shows it in the response pane, for a terminal that does not pass OSC 52
on. Secrets are not in it: each is a shell variable, such as `"$token"`
for `{{token}}`; a comment above the command names the variables to
set, and the command stops before curl runs if one is not set. A request
whose text holds a secret value outside a placeholder is not copied.
Text with control characters, such as a tab in a body, is quoted as
`$'...'`, which bash and zsh read.

## Checks and captures

`# @assert` checks a response, and `# @capture` takes a value from it for
the requests after it, such as a token from a sign-in:

```http
### Sign in
# @name login
# @assert status == 200
# @capture token = $.token
POST {{host}}/login
Content-Type: application/json

{"user": "ada", "password": "{{password}}"}

### The signed-in user
# @name me
# @assert status == 200
# @assert jsonpath $.name == "Ada"
GET {{host}}/me
Authorization: Bearer {{token}}
```

```console
$ vegtam run session.http -e dev
### session.http#login
HTTP/1.1 200 OK (112ms)

{
  "token": "***"
}

✓ status == 200
captured: token

### session.http#me
HTTP/1.1 200 OK (35ms)

{
  "id": 1,
  "name": "Ada"
}

✓ status == 200
✓ jsonpath $.name == "Ada"
```

A captured value is a secret unless the directive says `plain`: it is
masked from the response it came from onwards, and requests show it as
`{{token}}`. A failed assertion makes the exit code 1, and JSON output
has the outcome of each in `asserts`. [docs/FORMAT.md](docs/FORMAT.md#directives)
lists the checks and the sources.

## Import from Postman

`import postman` turns a Postman export, one collection or the directory
of a data export with its environments, into `.http` files, one per
folder, and environment files. Values that look like secrets go to the
private environment file rather than to a `.http` file:

```console
$ vegtam import postman postman-export -o api
Imported 25 of 30 requests from 2 collections into api, with 2 environments: dev, prod-eu.

request: 5 requests written commented out
  api/shop-api/shop-api.http#properties: method PROPFIND is not supported
  api/shop-api/shop-api.http#release-notes: a line of the body starts with ###, which would end the request
  api/shop-api/shop-api.http#draft: the request has no URL
...

body: 3 bodies and form fields not imported
  api/shop-api/zakazy.http#create-order: disabled form field coupon
  api/shop-api/zakazy.http#upload-receipt: formdata body
  api/shop-api/zakazy.http#search-orders-graphql: graphql body
...

Variables to check or set:
  id (unset): it has no value; set it in api/shop-api/http-client.env.json
  token (secret): check its value in api/shop-api/http-client.private.env.json
...

Keep the http-client.private.env.json files out of version control: they hold the secrets.

Check the requests without sending them: vegtam run api --dry-run -e dev
```

Scripts are not imported; [docs/FORMAT.md](docs/FORMAT.md#importing-from-postman)
lists what is and what is not.

## Documentation

- [docs/FORMAT.md](docs/FORMAT.md): the supported `.http` subset,
  assertions and captures, environment files, commands, secrets, and
  importing from Postman.
- [docs/AUTOMATION.md](docs/AUTOMATION.md): driving vegtam from scripts
  and agents: the JSON output and its stability, exit codes, dry runs,
  policy, limits and secret masking.
- [docs/DECISIONS.md](docs/DECISIONS.md): design decisions and why.

## Build

Requires Go 1.27 or newer.

```sh
make build        # builds ./vegtam
./vegtam version
```

## Test

```sh
make test
```

`make check` runs the whole gate: golangci-lint, the tests with the race
detector, and the other checks a change must pass. It needs golangci-lint
v2.15.0; [CONTRIBUTING.md](CONTRIBUTING.md) says how to install it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md): the gate, the rules it cannot
check, and how commits are written.

## License

MIT, see [LICENSE](LICENSE).
