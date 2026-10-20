# The .http format

vegtam reads the request files of the JetBrains HTTP Client and the VS Code
REST Client: plain text, one or more requests per file. It supports the
subset of that dialect described here. Anything outside the subset is an
error that names the file and line; nothing is skipped silently or sent as
part of a body.

```http
### List users
# @name list-users
# @assert status == 200
GET {{host}}/users?limit=10
Accept: application/json
Authorization: Bearer {{token}}

### Create a user
// @name create-user
POST {{host}}/users HTTP/1.1
Content-Type: application/json

{"name": "Ada", "email": "ada@example.com"}

###
# @name upload
POST {{host}}/upload
Content-Type: application/json

< ./payload.json
```

## Requests

**Separator.** A line starting with `###` ends the previous request. Text
after `###` is a comment. The first request needs no separator.

**Comments.** Lines starting with `#` or `//`, before the request line or
among the headers. In a body they are body text.

**Request line.** `METHOD URL`, optionally followed by an HTTP version.
The method is one of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`,
`OPTIONS`, `TRACE`, `CONNECT`, in upper case. The URL may contain
placeholders, including ones with spaces inside the braces
(`{{$env BASE_URL}}/items`). The version is what the request speaks:

| Version | Speaks |
|---|---|
| none | HTTP/2 when the server offers it over TLS, HTTP/1.1 otherwise |
| `HTTP/1.1` | HTTP/1.1 only |
| `HTTP/2`, `HTTP/2.0` | HTTP/2 over TLS only; over `http` it is an error |
| `HTTP/2 (Prior Knowledge)` | HTTP/2 without agreeing on it first: h2c over `http`, h2 over `https` |

`HTTP/3` is an error. `--http1.1`, `--http2` and `--http2-prior-knowledge`
override the line for a whole run; the response says what was spoken.

**Headers.** `Name: value`, one per line, right after the request line. The
name is an RFC 9110 token; the value may contain placeholders. A header
named `Host` sets the request's host.

**Basic credentials.** `Authorization: Basic {{user}} {{password}}`, the
shortcut of JetBrains, REST Client and httpyac, goes on the wire as
`Basic` and the base64 of `user:password` (RFC 7617). The user and the
password are a word each, literal text or placeholders, so that the
password can stay in the private environment file. Words are split at
the spaces of the text as written: the value of a secret may hold a
space, a value of `http-client.env.json` may not. `Basic` and one word,
the encoded form, is sent as it is. A user with a colon in it is an
error, since Basic cannot carry it. The encoded form is masked like the
secrets in it, and the header is dropped on a redirect to another
origin, as every `Authorization` header is.

**Body.** Everything after the first blank line, up to the next `###` or
the end of the file, taken verbatim. Blank lines at its start and end are
dropped, and line endings become `\n`. Placeholders in the body are
resolved.

**Body from a file.** A body consisting of one line `< path` is replaced by
the contents of that file, sent as is: placeholders in the file are not
resolved. The path is relative to the directory of the `.http` file and
must stay inside it: an absolute path, a path that leads out with `..`
and a symbolic link to a file elsewhere are errors, so that a `.http`
file cannot send a file from elsewhere on the machine. It must be a
regular file of at most 16 MiB: a directory, a named pipe, a socket or a
device is an error, before anything is read from it.

**Names.** `# @name <id>` or `// @name <id>` names the request that
follows. An id consists of letters, digits, `.`, `_` and `-`, is not a
number, and is unique within its file. A request is addressed as
`file.http#id`, or by position as `file.http#2`.

**Encoding.** UTF-8; a byte order mark is ignored; CRLF and LF line endings
both work.

## Directives

vegtam's own extensions are comments, so other tools ignore them:

| Directive | Meaning |
|---|---|
| `# @name <id>` | names the request |
| `# @assert <check>` | a check on the response, such as `status == 200` |
| `# @capture [plain] <name> = <source>` | takes a value from the response for the requests after it, such as `token = $.token` |
| `# @tag <tags>` | labels for selecting requests |
| `# @no-log` | keeps the request out of the history of runs, as in JetBrains, kulala and httpyac |
| `# @no-cookie-jar` | the request neither sends the cookies of the run nor keeps those its response sets (see [Cookies](#cookies)) |
| `# @timeout <time>` | lowers the read timeout, as in JetBrains: how long to wait for data once the request is sent |
| `# @connection-timeout <time>` | lowers the connect timeout, as in JetBrains: DNS, TCP and the TLS handshake |
| `# @max-time <time>` | lowers the time limit of the whole exchange, as curl's `--max-time` |

Directives go before the request line or among the headers, and each
but `@no-log` and `@no-cookie-jar`, which take none, needs a value. Their values are taken
as written: placeholders in them are not resolved, so
`header Authorization == "Bearer {{token}}"` compares with that very
text. `@tag` is kept with the request but not
used yet. Any other `# @word`, and an `@assert` or `@capture` outside the
grammar below, is an error with the file and line, also for
`--dry-run`, which parses directives but evaluates none; the
directives of other clients below are the exception.

### Time limits

A time is a number of seconds (`30`), a number with a unit, `ms`, `s` or
`m`, with or without a space (`500 ms`, `2m`), or a Go duration
(`1m30s`); `0` or `none` is no limit. Note that httpyac reads a bare number as
milliseconds: vegtam reads it as JetBrains does. A directive may only
lower the limit that the flag of the run gives (`--read-timeout`,
`--connect-timeout`, `--max-time`): one above it, `0` included, is a
warning, and the flag's limit holds. Each comes once per request.

### Directives of other clients

A `.http` file only ever makes the transport stricter: what weakens a
check or belongs to the machine comes from the command line. The
transport directives of other clients are errors that say what to use:

| Directive | Client | Instead |
|---|---|---|
| `@no-reject-unauthorized` | httpyac | `--insecure`, at a terminal |
| `@proxy`, `@no-proxy` | httpyac | `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` |
| `@kulala-curl-...`, and `@curl-...` before kulala 6 | kulala | the flags of `vegtam run` |
| `@setting insecure`, `proxy`, `http-root-cas`, `http-client-cert`, `http-client-key` | resterm | `--insecure`, the environment, `--cacert`, `--cert` and `--key` |

`@note`, `@prompt`, `@sleep`, `@ratelimit` and resterm's other
`@setting`s do not touch the transport: they are ignored with a warning,
and the request runs. Note what that means for `@note`, with which
httpyac asks before sending: vegtam does not ask, though the terminal
interface asks before any method but GET, HEAD and OPTIONS.

### Assertions

`# @assert <check>` checks the response. A request may have any number of
them, and every one is evaluated. If any fails, the result has an error
of kind `assert` and the exit code is 1 (see
[AUTOMATION.md](AUTOMATION.md#exit-codes)); the response is still shown.

| Check | Passes when |
|---|---|
| `status == 200` | the status compares so; the operators are `==`, `!=`, `<`, `<=`, `>` and `>=` |
| `status in 200..299` | the status is in the range, both ends included |
| `header <Name> == "<value>"` | a value of the header is exactly `<value>`; the name is not case-sensitive |
| `header <Name> contains "<text>"` | a value of the header contains `<text>` |
| `header <Name> exists` | the response has the header |
| `body contains "<text>"` | the body contains `<text>` |
| `jsonpath <path> == <JSON>` | the value at the path equals a JSON value: `true`, `42`, `"Ada"`, `null`, `[1, 2]`, `{"id": 1}` |
| `jsonpath <path> contains "<text>"` | the value at the path is a string that contains `<text>` |
| `jsonpath <path> exists` | the body has a value at the path, `null` included |
| `duration < 500ms` | the request, body included, took less; `<=` works too, with Go durations such as `2s` or `1m30s` |

Quoted text is a JSON string, so `"say \"hi\""` and `"\u00e9"` work.

**Paths.** A path starts with `$` and continues as a plain
[jq](https://jqlang.org/) path, without spaces: names (`$.token`,
`$.user.id`), quoted keys (`$["first-name"]`, `$."first-name"`) and
array indexes (`$.items[0]`, `$.items[-1]` for the last), optionally
ending in `|length`, the number of items, keys or characters. Nothing
else: no functions, slices, iteration, `?` or other pipes, so a path
only ever points at a value in the body and never computes a new one,
such as a part or an encoding of a secret, which masking would not
recognise. A path that goes into a value that is neither an object nor
an array, such as `$.name[0]` on a string, does not fit the body; a
missing key or index is absent. Numbers compare exactly:
`12345678901234567890` keeps all its digits, and `43.0` equals `43`. A
body that is not JSON, or that `--max-body` cut off, fails every
`jsonpath` check; that is a failed check, not an error.

Each outcome has the value checked, from the response and masked as the
response is: the status, the duration, the header's values joined with
`, `, the body, or the path's value as JSON; or, in parentheses, why
there is none, such as `(absent)` or `(the body is not JSON)`.

### Captures

`# @capture <name> = <source>` takes a value from the response and sets
the variable `<name>` for the requests after this one:

```http
### Sign in
# @name login
# @capture token = $.token
# @capture plain user = $.user.id
POST {{host}}/login
Content-Type: application/json

{"name": "ada", "password": "{{password}}"}

### Uses what the sign-in returned
# @name me
GET {{host}}/users/{{user}}
Authorization: Bearer {{token}}
```

| Source | Value |
|---|---|
| `$.path` | the value at the path, as for `jsonpath`: a string as it is, a number or boolean as JSON (`42`, `true`); an object or array, as compact JSON, only with `plain` |
| `header <Name>` | the first value of the header |
| `status` | the status code |

- **Secret by default.** A captured value is a secret unless the
  directive says `plain`: it is masked in all output from then on,
  starting with the response it came from, and requests show it as its
  placeholder, `{{token}}`. A plain value is inserted as it is and shown.
- **Order.** "After this one" means the requests that `run` sends later
  in the same run: the rest of the file and, for a directory, the files
  after it. A captured variable takes precedence over the environment
  and is never written to a file. `run file.http#me` sends one request,
  with no earlier one to take values from: there `{{token}}` comes from
  the environment, if at all.
- **No value.** A source that finds no value is an error of kind
  `capture` for its request, exit code 2: a body that is not JSON or that
  `--max-body` cut off, a path that is absent or does not fit the body,
  `null`, a missing header, or an object or array for a secret capture,
  since masking knows the value as a whole and not as the body writes
  it. The other captures of the request are still taken. The variable
  then has no value, not even an older one or the environment's, and a
  request that uses it fails with a `variable` error that names the
  request whose capture took nothing. So does a request after a file
  that does not parse, for each variable that file captures.
- **One per variable.** A request captures each variable at most once.
- **Dry runs** send nothing, so they capture nothing: a captured
  variable stays a placeholder, and the URL or header that holds one is
  not checked.

The name follows the rules for variable names below; `plain` may itself
be a name, as in `plain = $.plain`.

## Placeholders

| Placeholder | Value |
|---|---|
| `{{name}}` | the variable `name`: captured by an earlier request of the run, or from the selected environment |
| `{{$env NAME}}` | the environment variable `NAME` of the vegtam process |
| `{{$cmd NAME}}` | the output of the command `NAME` of the nearest `http-client.cmd.json`, if that file is trusted |

Variable names start with a letter or `_` and continue with letters,
digits, `_`, `.` and `-`. Whitespace inside the braces is ignored. Values
are inserted as they are: not URL-encoded and not expanded again. A `{{`
without a closing `}}` is an error; there is no escape for a literal `{{`
yet.

## Environments

Variables come from two JSON files in the format of the JetBrains HTTP
Client:

```json
{
  "$shared": {"api_version": "v2"},
  "dev": {"host": "https://dev.example.test", "page_size": 20},
  "prod": {"host": "https://api.example.com"}
}
```

- `http-client.env.json` holds shareable values and can be committed.
- `http-client.private.env.json` has the same layout and holds secrets. It
  must never be committed; keep it in `.gitignore`.

For each `.http` file vegtam uses the nearest file of each kind: in the
file's directory or the closest directory above it. `-e <env>` selects an
environment. Its variables are, from lowest to highest precedence: public
`$shared`, the public environment, private `$shared`, the private
environment. Values are strings, numbers or booleans. Selecting an
environment that neither file defines is an error that lists the defined
ones.

`SSLConfiguration`, which JetBrains reads from these files, is accepted
and not applied, with a warning: `verifyHostCertificate: false` does
not turn off the check of server certificates, and the client
certificate comes from `--cert` and `--key`.

Without `-e`, no environment file is read and only `{{$env NAME}}`
resolves. Every unresolved placeholder is an error; all the names missing
from a request are reported together.

## Commands

`{{$cmd NAME}}` takes a value from a command, such as a password
manager's command-line tool, so that the secret is in no file at all.
The commands are in `http-client.cmd.json`; vegtam uses the nearest one
from the `.http` file's directory upwards, as for environment files:

```json
{
  "TOKEN": {"argv": ["op", "read", "op://dev/api/token"], "timeout": "10s"},
  "DB_PASSWORD": {"argv": ["pass", "show", "dev/db"]}
}
```

- `argv` is the program and its arguments. There is no shell: no
  globbing, no variables, no pipes. A program without a `/` is looked up
  in `PATH`; a relative path such as `./bin/token` is relative to the
  directory where `http-client.cmd.json` is.
- The command runs in that directory, with vegtam's environment, no
  input and, on Unix, no terminal (in a session of its own), for at most
  `timeout`, a Go duration (`30s` by default). It may leave processes
  behind; its own exit status is what counts.
- So a command must get the secret without asking at the terminal: from
  an agent or a cache it has unlocked before, or with a window of its
  own. One that asks anyway finds nothing on its input and cannot open
  `/dev/tty`; it fails at once, and the error says why, rather than wait
  for an answer under the terminal interface, which reads every key. A
  program that finds the terminal by its name is beyond this: gpg-agent
  does so through `GPG_TTY` for `pinentry-curses`. Give it a graphical
  pinentry, or unlock the agent before.
- Its standard output, less one final line break (`\n` or `\r\n`), is
  the value. A command that exits with an error is an error of kind
  `variable` with the first KiB of what it wrote to standard error, in
  which only the secrets vegtam knows are masked; so is a command that
  prints nothing, prints more than 1 MiB or runs out of time.
- Each command runs at most once per run, before the first request is
  sent; every request that uses it gets the same value.
- Any other field, a key that appears twice, data after the object, a
  name that is not a variable name, or an empty `argv` makes the file an
  error.

The value is a secret. `http-client.cmd.json` itself holds no secret,
only how to get them, so it can be committed.

**Trust.** A command file runs nothing until a person trusts it, much
as `direnv allow` does for `.envrc` files: `vegtam trust <dir>` records
where the file is and a SHA-256 of it and of the files its commands
name by relative paths, such as `./bin/token`. If any of them changes,
the file is no longer trusted; a symbolic link to a trusted file
elsewhere is not trusted either. A `{{$cmd NAME}}` from a file that is
not trusted is an error of kind `policy`, exit code 6, whose message
gives the `vegtam trust` command to run after reading the file; see
[AUTOMATION.md](AUTOMATION.md#policy). `--dry-run` and `show -e` check
that the file is trusted and has the command, but run nothing: the
request shows `{{$cmd NAME}}`.

## Secrets

Values from `http-client.private.env.json`, from `{{$env NAME}}` and
from `{{$cmd NAME}}` are secrets, and so are captured values not marked
`plain`. A resolved
request holds only their names; the values are inserted
when the request is sent. Wherever a request is shown, a secret appears as
its placeholder (`Bearer {{token}}`). In other text that might contain a
value, such as error messages and response headers and bodies, every
secret value, including its URL- and JSON-escaped and base64-encoded
forms, is replaced with `***`.

When a redirect leads to another origin (scheme, host or port),
`Authorization`, `Cookie`, `Proxy-Authorization`, `Referer` and every
header whose value holds a secret are dropped for the rest of the redirect
chain. No redirect sends the URL it came from as the `Referer`, as other
clients do: its query may hold a token. A `Referer` the request has itself
is sent on as far as its origin. A 307 or 308 redirect sends the body again, so one to another
origin is refused if the body holds a secret. A redirect from `https` to
`http` is always refused. A refused redirect is a `network` error.

## Cookies

A run keeps the cookies that responses set, for the requests after them,
as browsers and the other `.http` clients do: a request that signs in
and one that uses the session work in one run. In the terminal
interface the cookies last until another environment is chosen. They
are kept in memory only, never written to a file, and the next run
starts without any.

Which cookie goes to which request follows RFC 6265, with the public
suffix list: a cookie goes to the host that set it, or to the domain
its `Domain` names and the hosts below it, never to another site, and a
`Secure` one only over `https`. A cookie is not kept if its `Domain` is
a public suffix, such as `co.uk`, or another site; if it is `Secure` and
was set over `http`, or would replace a `Secure` one from `http`; if a
`__Secure-` or `__Host-` prefix lacks what RFC 6265bis asks of it; if
its name and value are over 4096 bytes, or its `Domain` or `Path` over
1024; or past 50 cookies a site and 300 in all. Unlike in browsers,
`localhost` is no exception to `Secure`: http to it may go through a
proxy. A host that is not ASCII keeps no cookies.

`# @no-cookie-jar` keeps one request away from the cookies of the run:
none is sent, and none its response sets is kept. JetBrains reads the
directive as "keep none" only. `--no-cookies` turns the cookies off for a
whole run. A `Cookie` header written in the request is sent either way,
and dropped on a redirect to another origin.

A cookie's value is a secret: the output names the cookies sent and set,
never their values; a `Set-Cookie` header shows `***` for the value, and
a value of 8 bytes or more is masked wherever else it shows, such as in
a body that echoes the session. A shorter one, such as `lang=en`, is no
credential, and masking it would mask every `en`.

## Importing from Postman

`vegtam import postman <export> -o <dir>` converts a Postman export: a
collection file (Collection v2.1 or v2.0), or the directory of an export
with collections, environments and globals, such as Postman's data
export. Files are recognised by their contents; any other file is
reported and skipped.

```
api/
  shop-api/                        one directory per collection
    http-client.env.json           $shared and one environment per Postman environment
    http-client.private.env.json   the secrets, if there are any
    shop-api.http                  the requests at the top of the collection
    products.http                  the requests of the folder Products
    products/admin.http            the requests of its subfolder Admin
```

File and request names are slugs of the Postman names: lower-case ASCII
letters, digits and `-`, with Cyrillic transliterated, and `-2`, `-3` for
a name already taken in its directory or file. The `###` line keeps the
Postman name; `# @name` holds the slug.

| Postman | Imported as |
|---|---|
| method and URL | the request line: the raw URL as is, or one built from its parts; `:name` path variables filled in; a URL without a scheme gets `http://`, as Postman sends it |
| headers | headers; disabled ones as comments |
| raw body | the body as is, with the `Content-Type` Postman sends for its language unless the request sets one |
| urlencoded body | an `application/x-www-form-urlencoded` body of the enabled fields, encoded around their placeholders |
| formdata, file and graphql bodies | not imported: a comment and the report |
| bearer auth | `Authorization: Bearer {{...}}` |
| basic auth | `Authorization: Basic {{...}}`, with the encoded credentials in the private file; if they contain placeholders, a variable to set, since vegtam does not encode values |
| apikey auth | a header or a query parameter |
| inherited auth, noauth | as in Postman: a request without its own auth takes that of its nearest folder or of the collection |
| oauth2 and other auth types | not imported: a comment and the report |
| pre-request and test scripts | neither imported nor run; the status a test checks for becomes `# @assert status == N` |
| saved responses, request settings | not imported, reported |

**Variables.** Globals and collection variables go to `$shared`, the
collection's taking precedence, and each Postman environment becomes an
environment of the same name as a slug: `Prod EU` becomes `-e prod-eu`.
An export without environments gets an empty one, `default`. Every
collection directory has both files with every environment in them,
because vegtam uses the nearest file of each kind and does not combine
it with files further up. Variable names vegtam does not accept, such as
`{{api key}}`, are renamed (`{{api_key}}`) everywhere. Postman's dynamic
variables, such as `{{$guid}}`, are kept and reported: vegtam does not
support them yet.

**Secrets.** No secret is left in a `.http` file or in
`http-client.env.json`:

- variables that Postman marks as secret, variables named like a secret
  (containing `token`, `key`, `secret`, `passw`, `pwd`, `credential`,
  `cookie`, `session` or `authorization`, in any case) and variables that
  auth refers to go to `http-client.private.env.json`, with all their
  values;
- a literal value in auth, or in a header, query parameter, form field
  or JSON body field named like a secret, moves to a new variable such as
  `shop_api_token` in the `$shared` of the private file, and the request
  refers to it. Text around a placeholder moves too:
  `sid=abc; theme={{theme}}` becomes `{{shop_api_cookie}}{{theme}}`. In
  a JSON body, so does every value inside an array or object under such
  a key, numbers included; the body is read token by token, so trailing
  commas and comments do not stop it. The variable holds the value as the
  request sent it, URL- or JSON-escaped, so the same bytes go on the
  wire.

Detection goes by name, so a secret under an ordinary name, such as a
token in a URL path, stays where it is: read the imported files before
committing them.

A variable whose value refers to other variables, such as
`"api_root": "{{base_url}}/v2"`, is imported as it is and reported:
vegtam inserts values without resolving placeholders in them.

**Checks.** Every request is parsed back before it is written. A request
that would not read back as it was, such as one without a URL, with a
method vegtam does not support, or with a body line starting with `###`,
is written commented out with the reason.

**Report.** The command prints how many collections and requests it
imported, what it did not import and why, by category, and the variables
to check (secrets whose values came from the export) or to set
(variables without a value); with JSON output, the `import` document
described in [AUTOMATION.md](AUTOMATION.md). It writes only inside `-o`,
and it overwrites no file without `--force`.

## Not supported yet

| Feature | What happens |
|---|---|
| request line without a method (`https://example.com`) | error |
| URL continued on indented lines | error |
| file variables (`@host = example.com`) | error |
| body file with variables (`<@ ./file`) | error |
| multipart bodies with `< file` parts | error |
| response handlers and output redirects (`> {% ... %}`, `> script.js`, `>> file`, `<> file`) | error |
| JetBrains directives such as `@no-redirect`, `@no-auto-encoding` | error |
| dynamic variables other than `$env` and `$cmd` (`$uuid`, `$timestamp`, `$random.*`) | error |
| environment values that are objects, such as `Security`, other than `SSLConfiguration` | error |
| WebSocket, gRPC and GraphQL requests | error (method not recognised) |
