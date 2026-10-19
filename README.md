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
vegtam schema                         # the JSON Schema of the JSON output
```

`vegtam --help` lists the exit codes.

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
  environment files, secrets, and importing from Postman.
- [docs/AUTOMATION.md](docs/AUTOMATION.md): driving vegtam from scripts
  and agents: the JSON output and its stability, exit codes, dry runs,
  limits and secret masking.
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

`make vet`, `make fmt` (gofmt check) and `make lint` (golangci-lint, if
installed) are available too.

## Contributing

Commit timestamps are kept in UTC: commit with `TZ=UTC git commit`.

## License

MIT, see [LICENSE](LICENSE).
