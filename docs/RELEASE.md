# Releases

A release of vegtam is on the
[releases](https://github.com/vidforull/vegtam/releases) page of
[github.com/vidforull/vegtam](https://github.com/vidforull/vegtam): four
archives, for macOS and Linux on amd64 and arm64; a `.deb` and an
`.rpm` for Linux on each ([Linux packages](#linux-packages));
`checksums.txt`, the SHA-256 sum of each file; and
`checksums.txt.sigstore.json`, a cosign signature of the sums. A tag
pushed to GitHub makes it: the release workflow runs the gate, then
[GoReleaser](https://goreleaser.com) builds, signs and publishes, as
`.goreleaser.yaml` says. The same commit builds the same bytes anywhere
([Reproducible builds](#reproducible-builds)).
[DECISIONS.md](DECISIONS.md#2026-10-20-releases) says why GoReleaser,
and [a later entry](DECISIONS.md#2026-10-21-releases-from-github-actions)
why releases are made on GitHub.

## Verifying a download

Download `checksums.txt` and `checksums.txt.sigstore.json` with the
files, and check the sums in their directory:

```sh
sha256sum -c --ignore-missing checksums.txt   # on macOS: shasum -a 256 -c --ignore-missing checksums.txt
```

Each file downloaded must say `OK`; `--ignore-missing` passes over the
files of the release that were not downloaded. Then check
`checksums.txt` itself with [cosign](https://github.com/sigstore/cosign):

```sh
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/vidforull/vegtam/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

`Verified OK` shows that `checksums.txt` was made by a workflow of this
repository on GitHub, and logged in Sigstore's transparency log; the
sums then vouch for each file. The stricter form names the workflow and
the tag, in place of `--certificate-identity-regexp` and its argument:

```sh
--certificate-identity https://github.com/vidforull/vegtam/.github/workflows/release.yml@refs/tags/v0.1.0
```

The `Source code` archives that GitHub adds to each release are made by
GitHub from the tag; neither the sums nor the signature cover them.

## Not signed or notarized by Apple

The cosign signature is not one that macOS knows. The binaries are not
signed with an Apple developer certificate, nor notarized by Apple. Go
signs a binary for macOS on arm64 ad hoc, which Apple silicon needs to
run it at all, but Gatekeeper trusts no such signature. A file
downloaded with a browser carries the quarantine attribute, and macOS
refuses to run a binary unpacked from it. Once the archive's sum is
checked, remove the attribute before unpacking it:

```sh
xattr -d com.apple.quarantine vegtam_0.1.0_darwin_arm64.tar.gz
tar -xzf vegtam_0.1.0_darwin_arm64.tar.gz
```

A file fetched with curl gets no such attribute.

## Linux packages

The `.deb` and the `.rpm` hold the binary of the Linux archive for
their architecture, as `/usr/bin/vegtam`, and `LICENSE` and `README.md`
in `/usr/share/doc/vegtam/`; in the `.deb` the license is `copyright`,
as Debian has it. Once the sum is checked, on amd64:

```sh
sudo apt install ./vegtam_0.1.0_amd64.deb
sudo dnf install ./vegtam-0.1.0-1.x86_64.rpm
```

On arm64 the names end in `_arm64.deb` and `.aarch64.rpm`. The version
inside a candidate's package is `0.1.0~rc.1`: dpkg and rpm sort a `~`
before anything else, so the candidate comes before `0.1.0`, which
installs over it as an upgrade. The file names have `-` in its place,
as `vegtam_0.1.0-rc.1_amd64.deb`, since GitHub renames a file with a
`~`. There is no apt or yum repository, and no Homebrew tap, yet: a new
version is installed the same way, from its release.

## Versions

Each version is tagged first as a release candidate, `vX.Y.Z-rc.N`, on
a commit of `main` that passes [Before a tag](#before-a-tag). Its
release is a pre-release: `prerelease: auto` in `.goreleaser.yaml`
makes one of any tag with a pre-release part. Its archives and
packages, as the release offers them, are then checked on macOS and
Linux; a fix goes to `main` as any change does, and makes the next
candidate. The version, `vX.Y.Z`, is tagged on the very commit of the
candidate that passed, so that every check holds for it. A pushed tag
is never moved: Go's module proxy and checksum database keep what a
version held once anyone fetched it, so a moved tag would give some
people other code than others, or a checksum error. A fix after a tag
is the next candidate, or the next patch version.

Versions follow [Semantic Versioning](https://semver.org), which puts
`0.1.0-rc.1` before `0.1.0`, and `rc.10` after `rc.9`. The archives and
`vegtam version` name a version without the `v` of its tag, as
`vegtam_0.1.0-rc.1_darwin_arm64.tar.gz`; `go install` of the tag says
`v0.1.0-rc.1`, as Go writes it. While vegtam has no release,
`go install github.com/vidforull/vegtam/cmd/vegtam@latest` installs the
latest candidate: Go's `latest` is the highest pre-release when there
is no release.

## Making a release

**Tools.** Go, the version that the `toolchain` line of `go.mod` names
(go1.27.2): the Go version is part of what a binary is. GoReleaser
v2.18.3 (`go install github.com/goreleaser/goreleaser/v2@v2.18.3`), the
version that the release workflow runs: another version may pack the
archives and packages otherwise, and their sums would then differ, so
`make release-check` refuses it. golangci-lint and govulncheck at the
versions the gate wants ([CONTRIBUTING.md](../CONTRIBUTING.md#tools)).

### Before a tag

On the commit of `main` to be tagged, with nothing changed:

```sh
git switch main && git pull --ff-only
git status --short        # prints nothing
make release-check        # make check, then goreleaser check
govulncheck ./...
```

Each must pass, with no `SKIPPED` in the output: `make check` skips
govulncheck, and `make release-check` goreleaser, if it is not
installed. govulncheck runs by hand too, so that a missing tool cannot
skip it. The release workflow runs the gate again, but a pushed tag is
never moved, so the commit is checked before it is tagged.

### Tag and push

Tags are annotated, and made in UTC, as commits are: a candidate, or
the version on the commit of the candidate that passed, `rc.2` here.

```sh
TZ=UTC git tag -a v0.1.0-rc.1 -m 'vegtam 0.1.0-rc.1'
TZ=UTC git tag -a v0.1.0 -m 'vegtam 0.1.0' 'v0.1.0-rc.2^{commit}'
```

[Build the tag](#building-a-tag) and check it first; until it is
pushed, `git tag -d v0.1.0-rc.1` still removes it. Then push the tag on
its own:

```sh
git push origin v0.1.0-rc.1
```

GitHub starts no workflow for a push of more than three tags at once,
so each tag goes in a push of its own.

### The release workflow

The push starts `.github/workflows/release.yml`. Its first job runs the
gate, `make check`, with a token that can only read, and refuses a tag
whose commit is not on `main`. Its second job starts once the first has
passed, and runs GoReleaser with `GORELEASER_CURRENT_TAG` set to the
tag that was pushed. GoReleaser builds the archives and packages,
writes `checksums.txt`, signs it with cosign, keyless, and publishes
the release, titled `vegtam 0.1.0-rc.1`. Its notes list the commits
since the previous tag, except those whose subject starts with
`docs:`, `readme:` or `test:`. The job then verifies the signature as
[Verifying a download](#verifying-a-download) does, with the exact
identity of the workflow at the tag. Only the second job can write to
the repository or ask for the token that cosign signs with
([CI.md](CI.md)).

### Building a tag

To check a tag before it is pushed, or to compare a release with a
build of your own, build the tag with nothing changed:

```sh
git switch --detach v0.1.0-rc.1
export GOTOOLCHAIN=$(awk '$1 == "toolchain" {print $2}' go.mod)
GORELEASER_CURRENT_TAG=v0.1.0-rc.1 goreleaser release --clean --skip=publish,sign
```

`--skip=publish,sign` builds and sums, and neither signs nor uploads:
no token is needed. `GORELEASER_CURRENT_TAG` names the tag to build.
The version shares its commit with its last candidate, and GoReleaser,
left to choose among the tags of a commit, would build `v0.1.0` as
`0.1.0-rc.2`.

`dist/` then holds `vegtam_<version>_<os>_<arch>.tar.gz` for each
target, with the binary, `LICENSE` and `README.md` in it, the packages,
such as `vegtam_<version>_amd64.deb` and
`vegtam-<version>-1.x86_64.rpm`, `checksums.txt`, the binaries in a
directory each, such as `dist/vegtam_linux_amd64_v1/vegtam`, and
GoReleaser's own metadata. From a commit that is not tagged,
`goreleaser release --snapshot --clean --skip=sign` builds the same set
with a version that ends in `-SNAPSHOT-<commit>`: `--snapshot` skips
publishing, but not signing. `goreleaser build --snapshot --clean`
builds the binaries alone. A snapshot builds a tree with changes too,
and its binaries say `+dirty` after the commit, while a release refuses
such a tree.

Check what was built, in the directory of the system you are on:

```sh
cd dist
sha256sum -c checksums.txt        # on macOS: shasum -a 256 -c checksums.txt
./vegtam_linux_amd64_v1/vegtam version --json
go version -m vegtam_linux_amd64_v1/vegtam
```

`vegtam version` names the version without its `v`, the full commit of
the tag (`git rev-parse 'v0.1.0^{commit}'`) and its date, in UTC.
`go version -m` shows `-trimpath=true`, `CGO_ENABLED=0` and
`vcs.modified=false`, but not the linker flags, which Go leaves out of
a binary built with `-trimpath`: `vegtam version` is how to see them.

## Reproducible builds

Two builds of one commit with the same Go and the same GoReleaser give
the same bytes: binaries, archives and packages alike. Nothing in them
depends on when or where they were built. Every time is the commit's:
the date the binary prints, its file time, the file times in the
archives and packages, and the build time an `.rpm` records. Paths are
trimmed, cgo is off, the archives and packages name root as the owner
of each file and fix its mode, and an `.rpm` names `reproducible` as
the host that built it. `GOFLAGS` must not be set, since it could
change how the go command builds.

That is how a release is checked apart from the workflow that built it:
build its tag again in a clone of your own, with the tools above, and
compare the sums with its `checksums.txt`. An empty build cache makes
the go command compile everything again rather than reuse an earlier
build:

```sh
dir=$(mktemp -d)
git clone --branch v0.1.0 https://github.com/vidforull/vegtam.git "$dir"
cd "$dir"
unset GOFLAGS
export GOTOOLCHAIN=$(awk '$1 == "toolchain" {print $2}' go.mod)
GORELEASER_CURRENT_TAG=v0.1.0 GOCACHE=$(mktemp -d) goreleaser release --clean --skip=publish,sign
diff <the release's checksums.txt> dist/checksums.txt && echo same
```

The sums cover the archives and packages, and with them the binaries.
The signature is not compared: each run makes its own.
