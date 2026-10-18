# vegtam

vegtam is a local-first CLI/TUI API client that runs requests from plain
`.http` files: no accounts, no cloud, no telemetry.

**Status:** early development. Nothing is stable yet.

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
