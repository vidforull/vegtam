# testdata

Synthetic only. Everything here is made up for tests:

- hosts use reserved names (`example.com`, `*.example`, `*.test`, `*.invalid`);
- tokens, keys and passwords are obviously fake;
- no real collections, exports, hosts, paths or people.

Tests never touch the network: requests go to `net/http/httptest` servers.

`postman/export` is a made-up Postman export laid out as Postman's data
export is; `postman/golden` is what importing it should give.

`cli` holds requests for the command tests and `flow` requests with
`@capture` and `@assert`; the tests write the environment files next to
them.
