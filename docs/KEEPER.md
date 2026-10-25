# The keeper

A program that runs vegtam for you, an AI agent or a script, runs in your
shell as you. It can read what you can: `http-client.private.env.json`,
your environment, what a command file prints. vegtam's own rule is that
such a run gets no secret value at all
([AUTOMATION.md](AUTOMATION.md#without-a-person-no-secrets)). The keeper
is how it may still send requests that need one: a process of yours, in
a terminal of yours, that holds the values, sends the request itself,
asks you first, and gives the program the response with nothing of a
secret in it. It is to vegtam what `ssh-agent -c` is to ssh keys.

## Set it up

1. Put your secrets in the store, an encrypted file of your own
   (`secrets.enc` in vegtam's configuration directory), and say where
   each may go:

   ```console
   $ vegtam secret set token
   value of token:
   new password for the store of secrets (/home/ada/.config/vegtam/secrets.enc):
   the same again:
   Put token in the store.
   token  bound to none: goes nowhere
   $ vegtam secret allow token https://api.example.com
   token  https://api.example.com
   ```

   `vegtam secret import http-client.private.env.json -e dev` moves the
   values of a private environment file into the store, with the origins
   its `$allow` gives them. The file is left as it was: delete it, or
   the values in it, once the store holds them. The keeper never reads
   it.

2. Send the runs without a person to the keeper, in the operator's
   policy, `~/.config/vegtam/policy.json`:

   ```json
   {"secrets": {"unattended": "keeper"}}
   ```

3. Start it in a terminal of its own, and leave it there:

   ```console
   $ vegtam keeper
   password of the store of secrets (/home/ada/.config/vegtam/secrets.enc):
   vegtam keeper: listening at /run/user/1000/vegtam/keeper.sock; 1 secret in the store; it asks before each request with a secret. Ctrl-C stops it.
   ```

When an agent runs `vegtam run api.http#me --json`, the keeper asks:

```
vegtam keeper: a request asked by pid 4242 (agent) uid 1000
  GET https://api.example.com/me
  headers Authorization; no body
  secret {{token}}, in header Authorization, goes to https://api.example.com: bound to it
To send it, type 7k2q and Enter; anything else, or no answer in 60s, does not send it.
> 7k2q
  sending it.
pid 4242 (agent) uid 1000: GET https://api.example.com/me: HTTP 200
```

You type the code, it sends the request, and the agent gets the
response, with every secret masked and the credentials a response hands
out, such as `Set-Cookie` or an `access_token`, as `***`
([redacted](AUTOMATION.md#without-a-person-no-secrets)). Anything else
you type, or no answer within a minute, and the agent gets an error of
kind `policy`, exit code 6: "the keeper's operator did not confirm it".
A code, not Enter: a key pressed by reflex, or by a stray process, must
not send a secret. Ctrl-C stops the keeper, and so does the end of its
input (Ctrl-D): no one is left to answer.

`secrets.keeper_asks: "unbound"` in the policy makes it ask only for a
request that would send a secret where it is not bound: one whose
secrets all go where they may goes without a question, unless it runs a
`{{$cmd NAME}}`. A command runs on your side, as you, so the keeper asks
of it whatever `keeper_asks` says, and shows it whole, with its file:

```
vegtam keeper: a request asked by pid 4242 (agent) uid 1000
  GET https://api.example.com/me?key={{$cmd KEY}}
  no header; no body
  secret {{$cmd KEY}}, in the URL, goes to https://api.example.com: bound to it
  command KEY: /usr/bin/op read op://dev/api/key
  from /home/ada/api/http-client.cmd.json: it runs here, as you, once you type the code
To send it, type 3fx8 and Enter; anything else, or no answer in 60s, does not send it.
>
```

## What it does

- **It holds the values.** It asks for the store's password once, when
  it starts. Runs without a person name the secrets of a request, never
  hold them: `{{token}}` from the store, `{{$env NAME}}` from the
  keeper's environment, `{{$cmd NAME}}` from a command file you trusted
  before the keeper started (the command runs on the keeper's side, once
  you have read it in the question and typed the code).
  It reads no private environment file: the agent could have put one
  where the keeper would look.
- **It sends the request.** A run that needs it sends every request
  through it, from the first: the cookies of its responses and the
  values its captures take stay in the keeper, for the requests of the
  same run, and the agent gets their names alone. It sends as a run
  without a person does: the network policy, the guard and the
  operator's ceilings hold, and the flags of the agent's run do not
  reach it.
- **It checks where each secret goes**, as every run does: a secret of
  the store to the origins `vegtam secret allow` gave it, `{{$env NAME}}`
  and `{{$cmd NAME}}` to those of the policy, a captured value back to
  the origin it came from. A request that would send one elsewhere is
  asked about whatever `keeper_asks` says, with the secret marked as not
  bound; if you do not type the code, nothing is sent.
- **It keeps its own history**, in your history of runs as it was when
  the keeper started, each entry with the process it sent for (`for`);
  the agent's own entries say `keeper: true`.
- **It reads the policy and the trust store once,** when it starts: what
  weakens it is yours to change, and a program of yours can write either
  file. It says which command files it trusts:

  ```
  vegtam keeper: the commands it may run, once you type a code, are those of 1 command file trusted now: /home/ada/api/http-client.cmd.json.
  ```

  A change to the policy's `secrets`, or to the command files trusted
  (`trust.json`), while it runs is shown in its terminal. A file trusted
  since runs once the keeper starts again; a trust taken back, with
  `vegtam trust --revoke`, applies at once:

  ```
  the trust store changed: /home/ada/api/http-client.cmd.json trusted. A trust taken back applies now; one given, once the keeper starts again.
  ```

  Without a terminal, a program cannot trust a command file: `vegtam
  trust` fails with exit code 6. With a terminal of its own, under
  `script`, or by writing `trust.json` before the keeper starts, it can:
  hence the list above, and the commands in each question. The program
  of a command that PATH finds, such as `op`, is the one found when the
  question was put, shown by its path; before a command runs, the keeper
  hashes again the files it names, such as `./bin/token`: one changed
  while the question waited is not run.

## Protocol

Version 1: JSON, one document a line, over a unix socket at
`$XDG_RUNTIME_DIR/vegtam/keeper.sock`, or `vegtam/keeper.sock` under the
cache directory (`~/.cache` on Linux, `~/Library/Caches` on macOS),
mode 0600 in a directory of mode 0700. One keeper serves a socket: a
lock file beside it holds its pid. On connecting, the keeper writes
`{"keeper":1,"pid":<pid>}`, with `"multiplexer"` if it runs in one, and
the run answers `{"keeper":1}`; a run that gets another version stops,
with an error that names it. Then the run sends one request at a time,
`{"id":1,"send":{...}}`, the request as it resolved it, its secrets by
name, and the keeper answers
`{"id":1,"inbound":{"result":{...},"captured":[...]}}` or
`{"id":1,"error":{"kind":"policy","message":"..."}}`; an error without
an `id` is the keeper's last line, and closes the connection. A line is
at most 64 MiB, and a response body the keeper keeps for a run at most
32 MiB. The keeper learns which process connects from the system
(`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` and `LOCAL_PEERPID` on macOS),
shows it, and serves the processes of its own user alone; a run, in
turn, talks only to a keeper of its own user. `vegtam doctor` says
whether a keeper answers, and its pid.

## How it protects itself

- Other processes of yours may not attach to it or read its memory:
  `prctl(PR_SET_DUMPABLE, 0)` on Linux, which also keeps it from dumping
  core, and `ptrace(PT_DENY_ATTACH)` on macOS. The buffers of the
  password and of the key are locked in memory where the system lets
  them be (`mlock`), with a warning otherwise.
- It makes its files with `umask 077`.
- It refuses to start in tmux or screen, or under `script`, as its
  environment or any of its ancestors says, where another process can
  read what it shows and type into it; `--multiplexer` starts it there
  anyway, for one who means it.
- It serves eight runs at a time, and closes one that sends no request
  within two minutes. What a run writes is shown escaped, on one line,
  so that it cannot pass for a question of the keeper's.
- On Ctrl-C or SIGTERM it removes its socket and drops its store.

What a test checks and what it does not: the protocol, the lock, the
peer on Linux, the codes, the watch of the policy and of the trust
store, the commands in a question and the dumpable flag on
Linux have tests; on macOS, the peer, `PT_DENY_ATTACH` and the terminal
are built but not run by a test here, nor are the limits of `mlock`.

## The limits, honestly

- **One user, one zone of trust.** The keeper keeps the values out of the
  agent's process, its output and its history. It does not make the agent
  another user: a process of yours that is determined enough can read
  your files, the store's file included (it is encrypted, and the
  password is typed, never stored), watch your terminal, or wait for you
  to type a code for a request you did not read. Full isolation is the
  agent in a container, a virtual machine or under another user, with the
  socket passed to it (`ssh -L` forwards a unix socket, as vsock can);
  the keeper then shows as its peer the process that forwards, and the
  agent cannot reach your files at all.
- **A code is a person's attention, no more.** Read what it asks.
- **A file trusted before the keeper started is trusted.** `vegtam trust`
  wants a terminal, and a program can give itself one, under `script`,
  or write `trust.json`. The keeper lists the files it trusts when it
  starts, runs no file trusted after that, and shows each command's argv
  and program in its question: read them. It does not show what a
  script that a command runs says, nor what an interpreter loads from
  beside it; and a process of yours quick enough to change a script, or
  the program PATH found, between the keeper's last look and the start
  of the command, runs what it wrote.
- **By name, not by value.** What a response hands out is hidden from the
  agent by the name of its field or header (see
  [AUTOMATION.md](AUTOMATION.md#without-a-person-no-secrets)). A token
  under another name passes; it is a token of the response's server, and
  the agent holds no secret to send with it anywhere.
- **A person's confirmation can send a secret where it is not bound.**
  The keeper marks such a secret as NOT bound in its question; a code
  typed for it sends that request there, once, as `--confirm=<ref>` does
  for a person's own run. Bind it instead (`vegtam secret allow`) if it
  belongs there.
- **Not yet:** CI with secrets: a run without a person there has none,
  and no person to start a keeper. The terminal interface asks for the
  store's password before it starts, not when a request first needs it.
