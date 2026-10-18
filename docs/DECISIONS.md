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
