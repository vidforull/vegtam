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

**Request line.** `METHOD URL`, optionally followed by `HTTP/1.1` or
`HTTP/2`. The method is one of `GET`, `HEAD`, `POST`, `PUT`, `PATCH`,
`DELETE`, `OPTIONS`, `TRACE`, `CONNECT`, in upper case. The version is
recorded but does not force a protocol: vegtam uses HTTP/2 when the server
offers it over TLS and HTTP/1.1 otherwise. The URL may contain
placeholders, including ones with spaces inside the braces
(`{{$env BASE_URL}}/items`).

**Headers.** `Name: value`, one per line, right after the request line. The
name is an RFC 9110 token; the value may contain placeholders. A header
named `Host` sets the request's host.

**Body.** Everything after the first blank line, up to the next `###` or
the end of the file, taken verbatim. Blank lines at its start and end are
dropped, and line endings become `\n`. Placeholders in the body are
resolved.

**Body from a file.** A body consisting of one line `< path` is replaced by
the contents of that file, sent as is: placeholders in the file are not
resolved. A relative path is relative to the `.http` file.

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
| `# @assert <expression>` | a check on the response, such as `status == 200` |
| `# @capture <name> = <path>` | saves a value from the response, such as `token = $.token` |
| `# @tag <tags>` | labels for selecting requests |

`@assert`, `@capture` and `@tag` are parsed and kept with the request; they
are not evaluated yet. Each needs a value. Any other `# @word` is an error.

## Placeholders

| Placeholder | Value |
|---|---|
| `{{name}}` | the variable `name` of the selected environment |
| `{{$env NAME}}` | the environment variable `NAME` of the vegtam process |
| `{{$cmd NAME}}` | reserved: the output of a command configured for the folder; an error for now |

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

Without `-e`, no environment file is read and only `{{$env NAME}}`
resolves. Every unresolved placeholder is an error; all the names missing
from a request are reported together.

## Secrets

Values from `http-client.private.env.json` and from `{{$env NAME}}` are
secrets. A resolved request holds only their names; the values are inserted
when the request is sent. Wherever a request is shown, a secret appears as
its placeholder (`Bearer {{token}}`). In other text that might contain a
value, such as error messages and response headers and bodies, every
secret value, including its URL- and JSON-escaped forms, is replaced with
`***`.

When a redirect leads to another origin (scheme, host or port),
`Authorization`, `Cookie`, `Proxy-Authorization`, `Referer` and every
header whose value holds a secret are dropped for the rest of the redirect
chain.

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
| JetBrains directives such as `@no-redirect`, `@no-cookie-jar`, `@timeout` | error |
| dynamic variables other than `$env` (`$uuid`, `$timestamp`, `$random.*`) | error |
| environment values that are objects (`SSLConfiguration`, `Security`) | error |
| WebSocket, gRPC and GraphQL requests | error (method not recognised) |
