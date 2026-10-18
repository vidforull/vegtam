# testdata

Synthetic only. Everything here is made up for tests:

- hosts use reserved names (`example.com`, `*.example`, `*.test`, `*.invalid`);
- tokens, keys and passwords are obviously fake;
- no real collections, exports, hosts, paths or people.

Tests never touch the network: requests go to `net/http/httptest` servers.
