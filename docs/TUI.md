# The terminal interface

```sh
vegtam                       # on a terminal: the .http files below the current directory
vegtam tui api/ -e dev       # a directory or a file, starting with the dev environment
```

The interface opens only when stdin and stdout are terminals. For a
script or an agent, `vegtam` prints its help instead, and `vegtam tui`
an error, both with exit code 2
(see [AUTOMATION.md](AUTOMATION.md#the-terminal-interface-is-for-people)).
`vegtam tui` takes the transport flags of `vegtam run`, `--max-body`
and `--no-history` (see [TRANSPORT.md](TRANSPORT.md)).

The terminal interface has three panes: the `.http` files and their
requests, the selected request, and the latest response. The request is
shown as it would be sent, with secrets as their placeholders, or, if it
cannot be resolved, as written, over what stops it. Its placeholders are
coloured by what they stand for: a plain value, a secret, a value an
`@capture` takes, or nothing. The response is shown as `run --verbose`
prints it: status and time, headers, what the request went through, the
body with JSON indented, and the outcome of each `@assert` and
`@capture`. From 80 columns the list
sits beside the other two panes, from 140 all three are side by side,
and in a narrower terminal they stack.

| Key | |
|---|---|
| `j`/`k`, `↓`/`↑` | move in the list; scroll the request or the response |
| `Tab`, `Shift-Tab` | next, previous pane |
| `/` | search the list by label, file name or URL; `Enter` keeps the search, `Esc` clears it |
| `Enter` | send the selected request; for a method other than GET, HEAD or OPTIONS, for a request with `# @note`, whose text it shows, and for one that would send a secret where it is not bound, after a second `Enter` (any other key leaves it unsent) |
| `Esc` | cancel the request in flight; hide a copied command |
| `y` | copy the selected request as a `curl` command |
| `z` | fold the JSON body of the response from depth 1, then 2, then not at all |
| `e` | choose the environment |
| `h` | list the latest runs; `Enter` goes to the request of one, `/` searches them, `Esc` closes the list |
| `Ctrl-L` | redraw the screen |
| `?` | list the keys; on a small terminal, `j`/`k` and `f`/`b` scroll them |
| `q`, `Ctrl-C` | quit |

In the request and response panes `f`/`b` scroll by a page and `d`/`u`
by half of one. A value that an `@capture` takes is a variable for the
requests sent after it, and a cookie a response sets goes with them,
until another environment is chosen. Each send
reads the environment files again and runs `{{$cmd NAME}}` again, so an
edited file counts at once. Secrets are masked as in the CLI's output,
and the interface writes no file but the history of runs.

A secret goes only to the origins it is bound to (see
[FORMAT.md](FORMAT.md#where-secrets-may-go)), and the request pane says
where, under `Secrets:`:

```
Secrets:
{{token}}  https://api.example.com
{{$env TOKEN}}  bound to no origin; refused for https://exfil.example
{{session}}  captured from https://login.example.com
```

`Enter` on a request that would send one elsewhere sends nothing, and
the response pane asks instead, with a line for each secret refused:

```
Send GET api.http#check?

{{token}} goes to https://exfil.example, but it may go only to https://api.example.com.

enter sends it, any other key does not.
```

A secret bound to none says `but it is bound to no origin`, and a
captured one `but it came from a response of https://login.example and
may go back only there`. A second `Enter` sends the request, its
secrets with it, to its origin, this once; any other key does not. If
the files change before that `Enter`, the interface asks again: `the
request has changed: enter again to send it`. The question about a
method or a note names such secrets too.

`y` puts the command on the clipboard through the terminal (OSC 52) and
shows it in the response pane, for a terminal that does not pass OSC 52
on. Secrets are not in it: each is a shell variable, such as `"$token"`
for `{{token}}`, and Basic credentials are `-u 'user:'"$password"`; a
comment above the command names the variables to set, and the command
stops before curl runs if one is not set. The cookies of the session are
not in it. A request
whose text holds a secret value outside a placeholder is not copied.
Text with control characters, such as a tab in a body, is quoted as
`$'...'`, which bash and zsh read.
