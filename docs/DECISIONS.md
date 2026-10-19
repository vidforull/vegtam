# Decisions

Architecture decisions, oldest first. Each entry records what was decided
and why; a later entry may supersede an earlier one.

## 2026-10-18: module path, license, CLI library

- **Module path:** `github.com/vidforull/vegtam`, Go 1.27. The skeleton has
  no third-party dependencies.
- **License:** MIT.
- **CLI library:** left for the first working version. It will be either `cobra` or
  `kong`, not both. Until then `cmd/vegtam` dispatches its single `version`
  command with the standard library.

## 2026-10-18: cobra for the command line

`spf13/cobra` (with `spf13/pflag`), not `kong`.

- **Completion.** cobra generates bash, zsh, fish and PowerShell completion
  and supports dynamic completion, so `run <file>#<TAB>` can later offer the
  request names straight from the parser. kong needs a third-party add-on
  for either.
- **Explicit commands.** A command is a plain value built in code; nothing is
  derived from struct tags. That keeps help text, argument checks and exit
  codes visible in one place per command, which matters for a CLI whose
  output and exit codes are a contract for scripts and agents.
- **Familiarity.** kubectl, gh, Hugo and many others use cobra; its help
  layout and GNU-style flags are what users and contributors expect.
- **Cost.** Two small modules: pflag and mousetrap (Windows only). kong has
  none, but the difference is not worth giving up the above.

Flags are GNU style: `--json`, `-e dev`. The single-dash long form the
skeleton accepted (`-json`) is gone. `--json` is a global flag. Commands
live in `internal/cli`; `cmd/vegtam` only wires up the process.

## 2026-10-18: strict parsing, secrets by reference, redirects

- **Strict .http parsing.** A line or directive outside the supported
  subset is an error with file and line, not skipped. A skipped
  `# @no-redirect`, or a response handler sent as body text, changes what
  goes on the wire without telling anyone; a script or an agent can act on
  an error. Lifting a restriction later stays compatible, adding one would
  not.
- **Secrets by reference.** Resolving a request yields `core.Text`: literal
  segments and `Secret{Name}` segments. Values stay in the environment
  loader and are inserted only when `exec` builds the request for the wire.
  Requests are shown with `Text.Masked()` (`Bearer {{token}}`); text that may
  carry a value back, such as errors from the network stack and response
  headers and bodies, goes through `core.Masker` (`***`, URL- and
  JSON-escaped forms included). The first layer cannot leak what it never
  held; the second catches values that come back.
- **Redirects.** Credentials and secret-bearing headers are dropped when a
  redirect leaves the first origin (scheme, host and port) and stay dropped
  for the rest of the chain. net/http alone keeps them for subdomains and
  for another port on the same host, and it sends the previous URL, query
  secrets included, as `Referer`.
- **Requests by position.** `file.http#2` addresses the second request, so
  requests without `# @name` can be run alone. Names may not be numbers,
  which keeps the two forms apart.

## 2026-10-19: output, exit codes, masking in layers

- **One document, shaped by the argument.** `run file#ref` prints one
  result; `run file` and `run dir` print `results`, even for a single
  request. A script knows the shape before running anything, rather than
  finding out from how many requests matched.
- **Additive stability.** Every document carries `schema_version`; fields
  are only added. The JSON Schema is written by hand, with descriptions
  meant for whoever reads it, and a test checks it against the Go types
  both ways. Generating it would need either a dependency or a generator
  that loses the descriptions. Error kinds are open strings, not an enum,
  so that a new kind does not break validation against an older schema.
- **Headers as lists, bodies as strings.** Headers are `{name, value}`
  pairs, as in HAR: they keep order and repeats, which a map loses. A
  body is a string; one that is not UTF-8 is base64 with `encoding`, so
  that no byte is lost or replaced.
- **Errors in the document too.** With JSON output every error is also in
  stdout, usage errors included, so that a program reads one stream. An
  error stops only its own request, as one failing package does not stop
  `go test ./...`; the exit code is the highest among the requests. A
  file that does not parse is one result, so that `run --dry-run` over a
  whole collection reports every problem at once.
- **Masking in three layers.** (1) `exec` errors never hold a secret
  value: net/http quotes the URL it was sending to, so it is replaced with
  the masked URL and any value left is masked. (2) `output` builds every
  document masked. This layer is required, not a convenience: a base64
  body and a value cut off by `--max-body` cannot be recognised later.
  (3) Everything the CLI prints, text and JSON, stdout and stderr, goes
  through the masker of the environment loader once more, so that a
  missed path still cannot print a value. JSON is masked in its decoded
  string values, which keeps the document valid; a JSON response body is
  masked that way too, which catches any escaping a server uses. Every request of a run
  is resolved before the first is sent, so the masker knows every secret
  before anything is printed. Masking by value over-masks short values;
  that is the price of never printing one.
- **Text for terminals only.** Text output shows control characters in
  responses and error messages as `\xNN`: what a server sends is
  untrusted and must not drive the terminal.

## 2026-10-19: importing from Postman

- **A .http file per folder.** A folder's own requests go to one file
  named after it, its subfolders to a directory of the same name next to
  it; a collection is a directory. A .http file holds several requests,
  so a folder stays one unit (`run products.http`) in Postman's order,
  and the tree is no deeper than the collection. A file per request
  would give as many files as requests and lose the order within a
  folder.
- **Environment files per collection.** vegtam uses the nearest file of
  each kind and does not combine it with files higher up, so a shared
  file at the top could not hold collection variables. Each collection
  directory gets its own two files with every Postman environment in
  them, as any environment applies to any collection in Postman; the
  directory runs and moves on its own. The private file is written even
  when empty, so that one in a directory above cannot take its place. An export without environments
  gets an empty `default`, because `-e` needs one to select.
- **Secret by name, across the export.** A variable that Postman marks
  as secret, that is named like a secret, or that auth refers to is
  secret everywhere in the export, and all its values go to the private
  file. vegtam ranks private `$shared` above the public environment, so a
  variable split between the two files could take a collection value
  over an environment one; kept in one file, Postman's order of globals,
  collection and environment holds. Literal values where secrets go
  (auth, and headers, query parameters, form fields and JSON body fields
  named like secrets), including text around placeholders, move to new
  variables, the same value to the same variable. Like masking, detection by name rather catches too much than
  too little; it cannot see a secret under an ordinary name.
- **Parsed back, else commented out.** Every request goes through the
  parser that will read it. One that would not read back as meant stays
  in its file as comments with the reason, so that nothing is lost, the
  file parses, and the report counts it.
- **Scripts are reported, not converted.** Running Postman's JavaScript
  would take an engine and would run code from an export; translating it
  would be guesswork. Only the status a test checks for carries over,
  as `# @assert`.
- **Writing.** The importer only builds files; the command writes them
  through an `os.Root`, so neither a name from the export nor a symbolic
  link in the output directory leads outside `-o`. Without `--force` it
  writes nothing if any file exists, rather than half an import.
