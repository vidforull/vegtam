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
