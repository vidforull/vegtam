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

## 2026-10-19: assertions and captures

- **gojq for paths, plain paths only.** `github.com/itchyny/gojq`, used
  as a library, is the one new dependency (with its `timefmt-go`). jq
  syntax is widely known, gojq is pure Go and compares numbers exactly,
  so a large integer in a body is not rounded. A path is written with a
  leading `$`, as in JSONPath (`$.items[0].id`), and parsed as
  `.items[0].id`; gojq's syntax tree must then be a plain path of names,
  quoted keys and integer indexes, with at most a final `|length`. A full
  jq program could turn a secret into a slice, a character, its base64
  or its lower case, which masking by value cannot recognise. For the
  same reason gojq only computes the keys of the path, with `path()`; the
  value is looked up in the decoded body by vegtam, in objects and arrays
  only, since gojq would also index into strings. gojq's error messages
  quote part of the value they fail on, so they are replaced with
  vegtam's own, which quote nothing.
- **Small, strict grammar.** `@assert` knows status, header, body,
  jsonpath and duration checks, and nothing else; a check outside it is
  a parse error when the file is read, so `--dry-run` finds it. A
  general expression language would be a scripting language by another
  name, which this stage does not have.
- **A failed assertion is a result, not a failed request.** It has its
  own exit code, 1, the lowest after success: the request was sent, and
  its response is in the output for whoever looks into the failure.
  Every assertion is evaluated, so one run reports them all. Actual
  values are masked as the response is, a body as a body and a path's
  value as JSON, so that every escaped form is found, and only then cut
  at 200 bytes; error messages name only the expressions, since a cut
  body could split a secret where masking cannot see it.
- **Captured values are secrets by default.** What one takes from a
  response is mostly a token or a session id. A capture left unmarked
  then masks a value that did not need it, which is visible and easy to
  fix with `plain`; the other default would print a token in every
  later response and error. Masking starts with the response the value
  comes from. A secret capture takes a string, number or boolean, not an
  object or array: masking would know the compact JSON of it, not the
  values inside as the body writes them.
- **Captures by position in the run.** A variable is captured for the
  requests after its directive, in the order `run` sends them, and takes
  precedence over the environment. Requests are still resolved before
  the first is sent, so that the masker knows the other secrets; a
  captured variable is then a secret segment marked as captured, and its
  value is looked up when the request is sent. Whether `{{token}}` means
  the environment's or the captured value is decided by where the
  request is in the run, not by when it is sent. A capture that takes
  nothing leaves its variable without a value: an older token, or the
  environment's, would be sent without anyone noticing. For the same
  reason a file that does not parse still declares the variables its
  `@capture` lines name, found line by line, and a request captures a
  variable once at most.
- **Dry runs and late values.** A dry run sends nothing and so captures
  nothing. Its captured variables are late (`core.ErrLate`): shown as
  placeholders, and the URL or header holding one is left unchecked. A
  stand-in value would make a URL such as `{{next}}`, captured from a
  `Location` header, fail the check for no reason.

## 2026-10-19: secrets from commands, trust as the first policy

- **Commands, not a plugin system.** `{{$cmd NAME}}` gets a secret from
  any tool that prints it (`op`, `pass`, `security`, `vault`), with no
  code in vegtam for each; the keychain integration planned later can
  sit next to it. The command file holds how to get secrets, never the
  secrets, so it can be committed with the requests.
- **No shell.** Commands are argv lists run with os/exec. A shell would
  bring quoting, expansion and injection along with it; anyone who wants
  a pipeline can write a script and name it in argv. The working
  directory is the command file's, so that a relative script path means
  the same for every `.http` file that uses it.
- **Run once, before sending.** A command runs while requests are
  resolved, once per run, so that the masker knows its value before
  anything is printed and a prompt from a password manager comes once.
  A dry run and `show` run nothing.
- **Trust like direnv.** A file of commands is code. `vegtam trust`
  records where it is and a SHA-256 in the user's config directory,
  outside any collection, so a cloned repository, a pulled change or an
  edited file runs nothing until a person has looked at it. The sum
  covers the file and the files its commands name by relative paths,
  since a script next to the file is as much code as the file; programs
  from `PATH` or absolute paths are the system's. The key is where the
  file is found, only its directory's links resolved, so that a link
  elsewhere to a trusted file does not borrow its trust. The command
  file's bytes that are hashed are the bytes parsed and run; a script it
  names is hashed just before it runs. The store is written to a new
  file and renamed, readable by its owner only, and ignored if it or its
  directory belongs to someone else or others can write it.
- **Policy has its own exit code.** An untrusted file is not a malformed
  request: a program has to tell "fix the file" (2) from "a person must
  allow this" (6). Trust is the first piece of the policy planned for
  vegtam; confirmation of unsafe methods and host allowlists will
  join it under the same kind and codes.

## 2026-10-19: the quality gate

- **Body files stay beside the request.** A `< path` body is read
  through an `os.Root` of the `.http` file's directory, so `..`, an
  absolute path or a symbolic link cannot lead out of it. A collection is
  often someone else's: without this, a cloned `.http` file could send
  `~/.ssh/id_ed25519` as a body to its own host. `filepath.Join` and
  `Clean` are no boundary, they only rewrite the path. JetBrains allows
  any path; payloads kept beside the collection have to move below it.
- **Redirects keep secrets and TLS.** A redirect from https to http is
  refused, secrets or not: the request was written for TLS, and what
  the server sends back, a cookie or a token, would cross in clear. A
  307 or 308 to another origin is refused when the body holds a
  secret: net/http sends the body again, and unlike a header it cannot
  be dropped. A 301, 302 or 303 turns the request into a GET without a
  body and is followed as before.
- **Files are written whole.** Import writes each file to a new file
  beside it, syncs and closes it, checking both, and renames it over the
  old one; the trust store did so already and now syncs too. A failed or
  interrupted write leaves the old file, never half of the new one, and
  a private file replaced this way gets 0600 even if the old one was
  0644. The directories vegtam makes are 0700: each collection holds a
  private environment file.
- **A panic is masked too.** Go prints a panic's value as is, and a bug
  could panic with a secret or an escape sequence in it. `cli.Run`
  recovers and prints the value and the stack as terminal text, masked
  with every secret the environment loader has read so far, which may be
  before the command has its own masker. It exits with 2, the code Go
  gives, so that the exit codes do not change. `import` reads no
  environment: the values of an export are data it writes, and a panic
  there is masked with nothing. The secret-output test covers panics,
  and a redirect error that names a URL other than the request's.
- **Terminal text is UTF-8.** Text output already showed control
  characters as `\xNN`; bytes that are not UTF-8 are now shown the same
  way. A lone 0x9b is the 8-bit form of CSI, which a terminal that does
  not read UTF-8 takes as the start of an escape sequence. Fuzzing the
  function found this at once, with the property every terminal string
  must have: valid UTF-8, no control characters but tab and line feed.
- **One gate, run by make.** `make check-fast` and `make check` are what
  "done" means for a change, for people and scripts alike; there is no
  CI yet. Rules a contributor has to remember are kept to what no tool
  checks, and each of those has a test (CONTRIBUTING.md lists them).
  The gate's own files change only in pull requests of their own, and
  suppressions are counted against a baseline from `origin/main`.
- **Set for the defects it must catch.** The linters are configured to
  catch an unclosed response body, a shadowed `err`, an empty
  `default:` hiding an enum case, and `defer f.Close()` on a file open
  for writing. A data race and a secret in an error are for the tests to
  catch, under the race detector and in the secret-output tests: no
  linter sees them. Hence:
  - govet's **shadow** is on: a shadowed `err` can lose an error, that
    of a rename for one, and the other linters let it through. A
    shadowed `err` is fixed with `=`.
  - errcheck runs **without the std-error-handling preset**, which lets
    `(*os.File).Close` through, and with it the write error that
    `defer f.Close()` loses on a file open for writing. Closes of
    interface values, writes through an `io.Writer` or into a
    tabwriter, and cleanup removals stay excluded; a write to or the
    Close of an `*os.File` is checked.
  - exhaustive keeps **`default-signifies-exhaustive: false`**: with
    `true` an empty `default:` would hide a missing case from it.
    Switches list every case; gojq's term types are ignored, as vegtam
    refuses all but a few in a `default`.
  - gosec **G115** stays on: an integer conversion from input gets a
    bounds check where it happens.
- **Smaller choices.** misspell has no locale, since the prose here
  is British. gocognit (30) skips tests, which are scripts of checks.
  sloglint waits for the first slog call. os/exec is allowed in
  `internal/core/env/cmd.go` only, and the process environment is read
  in two places, `{{$env NAME}}` and the trust store location. The
  points that open files by path carry a `//nolint` with the reason
  rather than an exclusion by file, so that a new one in the same file
  is still reported.
- **Write errors on stdout stay unreported.** As `writeJSON` already
  decided, a failed write to stdout or stderr has nowhere to go; errcheck
  excludes `fmt.Fprint*` to an `io.Writer` for that reason.
- **goleak when there is a goroutine.** vegtam's code starts none; the
  first package that does adds `goleak.VerifyTestMain`, and
  `go.uber.org/goleak` becomes a dependency of its tests only.
- **Fuzzing.** The parser, templates, masking and terminal text have fuzz
  targets with properties rather than examples. Their seeds are in the
  tests, and the parser's are the `.http` files in testdata; inputs that
  once failed are kept in `testdata/fuzz` and run with every `go test`.

## 2026-10-19: the terminal interface

- **Bubble Tea v2, Bubbles v2, Lip Gloss v2.** `charm.land/bubbletea/v2`
  v2.1.0, `charm.land/bubbles/v2` v2.2.1 and `charm.land/lipgloss/v2`
  v2.0.6, all MIT. v2 is the maintained line: the view is a value that
  declares the alternate screen rather than commands that toggle it, the
  keyboard is read correctly on more terminals, and Lip Gloss leaves
  colours to the program, which knows its terminal. The modules are at
  `charm.land`, not `github.com/charmbracelet`: their `go.mod` declares
  that path, and Go refuses the other. `charmbracelet/x/term`, which Bubble
  Tea brings along, tells `cmd/vegtam` whether stdin and stdout are
  terminals.
- **From Bubbles: viewport, key and help.** The request and response
  panes are viewports, with soft wrap; the keys are `key.Binding`s, which
  `help` lists on `?` and in the status line. The tree is a column of
  lines of vegtam's own: Bubbles' list brings fuzzy filtering, paging and
  a delegate API, more than it needs before there is a search. teatest is
  not used either: its v2 is an untagged module of `x/exp`. The tests call
  Update and View, and one runs the program on a pipe.
- **One way to send.** The interface holds no request logic.
  `internal/core/session` prepares and sends requests for it as for
  `run` and `show`. A session lasts while one environment is chosen, so a
  value an `@capture` takes is a variable for the requests sent after it,
  in the order a person sends them; choosing another environment starts
  a new session. The middle pane shows the selected request as written
  without an environment, and with one as a dry run that declares what the
  session has captured: `{{token}}` after a sign-in is a placeholder, not
  unresolved. Before each send the session reads the environment and
  command files again and runs its commands again, as a new run would,
  keeping only what it captured: what goes out is what the preview showed,
  an edited file or a new `vegtam trust` counts at once, and a command
  that failed, was canceled or gave a token that has since expired runs
  anew. `{{$cmd NAME}}` runs only when a request is sent.
- **Masked before laid out.** Every string a view holds, a body as much
  as a file or an environment name, is masked with the secrets of the
  sessions its text comes from, joined with `Masker.Join`: the one that
  sends, those of earlier environments, and the dry run that previews the
  selected request. It is then shown as the CLI prints text for a
  terminal (control characters, escape sequences and bytes that are not
  UTF-8 as `\xNN`), and only then laid out by Lip Gloss. A line cut to
  its pane cannot leave half a secret behind, and a server cannot drive
  the terminal. The response is masked again when it changes, not at
  every key: a large body would slow every key down. Bubble Tea writes to
  the terminal itself, not through the CLI's masked writer: it draws the
  screen in pieces, which masking each write could not follow.
- **One request in flight, with an owner.** A request runs on a
  goroutine that the interface starts and `Run` waits for, with a context
  that `esc`, `q`, Ctrl-C and SIGTERM cancel; a Bubble Tea command only
  brings back its result. Bubble Tea does not wait for the commands it
  runs, and drops one it is handed while the program ends. While the
  request is in flight, its goroutine alone uses the session.
- **Panics.** Bubble Tea recovers a panic, restores the terminal and
  prints the value and the stack itself, unmasked; with `TEA_DEBUG` set it
  also writes them to a file in the working directory. The interface
  recovers first, in Update, View and the request's goroutine, quits so
  that Bubble Tea leaves the alternate screen and raw mode, and panics
  again with the value and its stack once the program has ended:
  `cli.Run` prints them masked, as any panic. Only a panic inside Bubble
  Tea itself would still take Bubble Tea's way.
- **Asking first.** `enter` sends GET, HEAD and OPTIONS at once and asks
  before any other method, which may change something on the server: the
  start of the confirmation that policy will ask of agents.
- **vegtam alone.** When stdin and stdout are terminals, `vegtam` with no
  command opens the interface on the current directory. Otherwise it
  prints the help on stderr and exits with 2: a script or an agent that
  runs it by mistake gets a usage error, not a program waiting for keys.
- **Interrupts.** SIGINT and SIGTERM cancel the root context. A request
  or a command they stop fails with kind `canceled` and exit code 130,
  128 + SIGINT, as a shell reports a process that Ctrl-C ended: neither a
  network error nor an unresolved variable, which would send a script
  looking for a fault.
- **No files.** The interface writes nothing; the history of runs, when
  it comes, will decide what it keeps and where.
