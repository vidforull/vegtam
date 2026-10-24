# Transport

How vegtam sends a request: TLS, the HTTP version, time limits,
proxies, routes and sockets, redirects and cookies; what the operator's
policy allows a run without a person; and what `--verbose` says about
each exchange. The flags are those of `vegtam run` and `vegtam tui`; where
one has a counterpart in curl, [Flags](#flags) says how they differ.

## Where a setting comes from

What a request is sent with comes from three places, in this order:
what vegtam does on its own, the operator's policy file, and the flags
of `run` and `tui`. A `.http` or environment file may then only make a
request stricter. What weakens a check or belongs to the machine never
comes from a file, and when no person is at a terminal (stdin or stdout
is not one, or `--json` is given, as for a script or an agent) it comes
from the policy alone:

| What | `.http` file | Flag, a person at a terminal | Flag, no person | Policy |
|---|---|---|---|---|
| time limits | lower only: `@connection-timeout`, `@timeout`, `@max-time` | `--connect-timeout`, `--read-timeout`, `--max-time` | the same | `limits`: ceilings on flags and directives |
| HTTP version | the request line | `--http1.1`, `--http2`, `--http2-prior-knowledge` | the same | |
| CAs | no | `--cacert` | the same | `hosts`: for one origin |
| client certificate | no | `--cert`, `--key` | the same | `hosts`: for one origin |
| unchecked certificates | no: an error | `--insecure`, every host | `--insecure`, only the hosts of `network.insecure_hosts` | `network.insecure_hosts` |
| proxy | no: an error | `--proxy`, or the policy's, or the environment's | the policy's only; `--proxy` is an error | `network.proxy`, `network.no_proxy` |
| hosts that go direct | no | `--noproxy` | the same | `network.no_proxy` |
| the proxy's user and password | no | `--proxy-auth '$env NAME'` | the policy's only; `--proxy-auth` is an error | `network.proxy_auth: "$env NAME"`, for `network.proxy` alone |
| another address for a host | no: an error | `--resolve`, `--connect-to` | only those that the policy lists | `network.resolve`, `network.connect_to` |
| a unix socket | no: an error | `--unix-socket`, `--abstract-unix-socket` | only those that the policy lists | `network.unix_sockets` |
| loopback and private addresses | no | connected to | only those of `network.allow` | `network.allow` |
| cloud metadata, link-local, multicast, unspecified addresses | no | never | never | never |
| cookie jar | `@no-cookie-jar` | `--no-cookies` | the same | |
| where a secret may go | no | `--confirm=<ref>`, for that request, to its origin | no | `secrets`, for `{{$env NAME}}` and `{{$cmd NAME}}`; a value of `http-client.private.env.json`, its `$allow` |

## The policy

The policy is `$XDG_CONFIG_HOME/vegtam/policy.json`
(`~/.config/vegtam/policy.json` without `XDG_CONFIG_HOME`), and nothing
else: never a file of a repository, nor of the current directory.
Others must not be able to write it or its directory. Every field may
be left out:

```json
{
  "limits":  {"max_time_ceiling": "5m", "read_timeout_ceiling": "2m", "connect_timeout_ceiling": "30s"},
  "network": {"allow": ["127.0.0.1:8080", "localhost:3000", "10.0.0.0/8"],
              "proxy": "http://proxy.example.com:3128", "proxy_auth": "$env PROXY_AUTH", "no_proxy": ["localhost"],
              "insecure_hosts": ["dev.example.com:8443"], "resolve": ["api.example.com:443:127.0.0.1"],
              "connect_to": ["api.example.com:443:staging.example.com:8443"], "unix_sockets": ["/var/run/docker.sock"],
              "confirm": "mutations"},
  "hosts":   {"api.internal.example.com:443": {"cacert": "~/certs/corp.pem", "cert": "~/certs/me.pem", "key": "~/certs/me.key"}},
  "secrets": {"env": {"API_TOKEN": ["https://api.example.com"]},
              "cmd": {"TOKEN": ["https://api.example.com", "https://auth.example.com:8443"]},
              "unattended": "deny", "keeper_asks": "always"}
}
```

`vegtam policy` prints it and what applies to a run; `vegtam policy
--help` describes every field. A connection the policy does not allow
fails before anything is sent, with exit code 6 and a message that
names the entry to write: `address 127.0.0.1:8080 is private (loopback),
and no person is at a terminal; allow it in policy: network.allow`. The
address checked is the one each connection is made to, after the name
is looked up; through a proxy, which connects out of sight, the target
is looked up here and checked before the proxy gets the request, which
tells the local resolver the name, with `socks5h` too. The proxy looks
it up again, and may get another answer: its own rules are the last
word there. `network.confirm` is about requests, not the network: see
[AUTOMATION.md](AUTOMATION.md#confirmation).

`secrets` says where the values of `{{$env NAME}}` and `{{$cmd NAME}}`
may go, by `NAME`: `env` for environment variables, `cmd` for the
commands of any command file. Each origin is written as in `$allow`,
`https://host` or `https://host:port`. Nothing else binds these values:
they are the machine's, and `$allow` in `http-client.private.env.json`,
a file that a cloned repository can bring, binds only the values of that
file. It holds in every mode: a value that the policy does not bind
goes nowhere, unless a person at a terminal confirms the request (see
[FORMAT.md](FORMAT.md#where-secrets-may-go)). `vegtam policy --json`
lists them in `policy.secrets`, by placeholder.

`secrets.unattended` is what a run without a person does with a request
that needs a secret value: `"deny"`, the default, refuses it with exit
code 6, and such a run holds no secret value at all; `"keeper"` sends
it through the keeper, which holds the values in the person's terminal.
`secrets.keeper_asks` is when the keeper asks its person: `"always"`,
the default, or `"unbound"`, only for a request that would send a
secret where it is not bound. Both weaken what a run without a person
gets, so the policy alone says them, as it says `network.confirm`
([AUTOMATION.md](AUTOMATION.md#without-a-person-no-secrets),
[KEEPER.md](KEEPER.md)). The keeper reads the policy once, when it
starts, and sends with its rules for a run without a person: its
`network`, `limits` and `hosts`, not the flags of the run it sends for.

## Flags

| Flag | Default | Unlike curl |
|---|---|---|
| `--cacert <pem>` | the system's roots | adds to the system's roots; curl's replaces them |
| `--cert <pem>`, `--key <pem>` | none | offered to the origin of each request as written, never after a redirect elsewhere; PEM only, the key unencrypted (`--key <(openssl pkey -in key.pem)`) |
| `--insecure` | off | for a person at a terminal; without one, only for the hosts that the policy names in `network.insecure_hosts`; a warning on every run |
| `--connect-timeout <time>` | 10s | the whole of getting a connection: DNS, TCP, a proxy's CONNECT, the TLS handshake |
| `--read-timeout <time>` | 30s | no counterpart: how long the server may send nothing, once the request is sent |
| `--max-time <time>` | 2m | curl has no limit by default; `--timeout` is the old name |
| `--http1.1`, `--http2`, `--http2-prior-knowledge` | as negotiated | `--http2` is HTTP/2 over TLS or an error: no fallback, no upgrade of `http` |
| `--no-cookies` | a jar for the run | curl keeps no cookies unless asked; vegtam keeps them in memory, never on disk |
| `--proxy <url>` | the policy's, or the environment's | for a person at a terminal; http, https, socks5 or socks5h; no user or password in it |
| `--proxy-auth '$env NAME'` | none | for a person at a terminal: the proxy's user and password from a variable that holds `user:password`, never in the arguments; no request may read the variable |
| `--noproxy <hosts>` | `NO_PROXY` | in its place, and the policy's; `*` for all |
| `--resolve host:port:addr[,addr]` | none | as curl's; Host and TLS keep the name, the guard checks the address; not through a proxy |
| `--connect-to host:port:to_host:to_port` | none | as curl's; an empty part is any, or the one asked for |
| `--unix-socket <path>`, `--abstract-unix-socket <name>` | none | every request to the socket, the host of the URL in `Host`; no proxy |

A time is in seconds (`5`, `0.5`) or has a unit (`500ms`, `2m`, `1m30s`);
`0` or `none` is no limit. Directives may lower the limits of a request, and the
request line may ask for a version (see [FORMAT.md](FORMAT.md)).
More differences: the proxy is the policy's, or for a person at a
terminal that of `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, and one
without a port uses that of its scheme (80, 443, 1080 for SOCKS), where
curl uses 1080 for all; `socks5` is `socks5h`, the proxy looks up the
name, as in Go; `--verbose` masks secrets, where curl's `-v`
prints `Authorization` and `Cookie` as they are; `SSLKEYLOGFILE` is not
read; HTTP/3 is not supported.

## Redirects

Redirects are followed, and each secret is kept to the origins it may
go to. On the way to another origin, `Authorization`, `Cookie`,
`Proxy-Authorization` and every header that holds a secret are
dropped, and a 307 or 308 whose body holds a secret is refused. A
redirect to an origin that a secret in the URL is not bound to is
refused before that hop, as an error of kind `policy` in every mode: a
server that passes its query on, as an open redirect does, would send
the secret there. A redirect from `https` to `http` is always refused.
[FORMAT.md](FORMAT.md#where-secrets-may-go) has the rules.

## Diagnostics

`--verbose` also says what each request went through, after the
response headers, with every secret masked: each redirect and the
headers it dropped, the address connected to, the TLS version and
protocol agreed on, the server's certificate, when each phase ended, as
curl's `-w` names them, and the cookies sent and set. Here, for a
request that `--connect-to` sends to a server on 127.0.0.1, whose
response sets a session cookie and redirects to `/home`:

```
* 302 → /home · connected to 127.0.0.1:4443 · resolved by --connect-to · connect 515µs tls 2ms ttfb 3ms total 3ms
* cookies: set session
* connected to 127.0.0.1:4443 (reused) · resolved by --connect-to · TLS 1.3 · h2 · ttfb 270µs total 295µs
* certificate CN=api.example.com, issuer CN=Example Dev CA, expires 2027-01-31T23:59:59Z
* cookies: sent session
```

With `--json` the same is in `timing`, `remote_addr`, `resolved_by`,
`tls`, `proxy`, `redirects` and `cookies`, and after an error too, as far
as the request got. `resolved_by` names the flag that sent a connection
elsewhere than its host, as `--connect-to` above. There is no mode that
prints the exchange unmasked. [AUTOMATION.md](AUTOMATION.md#output)
describes each field.

## Cookies and Basic credentials

A run keeps the cookies that responses set for the requests after it,
in memory: a request that signs in and one that uses the session work in
one run, and the next run starts afresh. `# @no-cookie-jar` keeps one
request away from them, `--no-cookies` a whole run
([FORMAT.md](FORMAT.md#cookies) has the rules).
`Authorization: Basic {{user}} {{password}}`, as JetBrains' client
writes it, and `Basic {{user}}:{{password}}`, as REST Client and httpyac
do, go as Basic credentials, base64-encoded.
