# Continuous integration

The gate is `make check` ([CONTRIBUTING.md](../CONTRIBUTING.md#the-gate)).
`.github/workflows/check.yml` runs the same `make check` on GitHub, for
each pull request and each push to `main`, on a clean machine: no cache,
no tool that happens to be installed, no file that git does not track.
It mirrors the gate and does not replace it.

Its own steps only set up the tools, at pinned versions, and check them:

- **Actions** by the full SHA of a commit, with the release in a comment
  (`# v7.0.1`): a tag can be moved to other code, a commit cannot.
- **Go** by the `toolchain` line of `go.mod`; a step fails the job if
  another version was installed.
- **golangci-lint** by the SHA-256 of its release archive, checked
  before it is unpacked, and **govulncheck** by its module version. The
  job fails if govulncheck is missing, which `make check` would skip.
- **The suppression baseline** from `main`: a pull request gets `main`
  fetched as `origin/main`, so that it cannot raise its own baseline.

The workflow's token can only read the repository, and it uses no
secret. A pull request runs the workflow as it has it, so a change to
the workflow is a change to the gate.

To change a pinned version: golangci-lint and govulncheck are pinned
twice, in the `Makefile`, which refuses any other version, and in the
workflow; change both in one pull request of their own, golangci-lint's
`VERSION` and `SHA256` together, the sum taken from the release's
checksums file. Go follows the `toolchain` line of `go.mod`. An action
takes the SHA of the commit that its release tag names, and the release
in the comment beside it.
