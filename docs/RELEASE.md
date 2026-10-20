# Releases

A release of vegtam is four archives, for macOS and Linux on amd64 and
arm64, and `checksums.txt`, the SHA-256 sum of each, on the
[releases](https://github.com/vidforull/vegtam/releases) page of
[github.com/vidforull/vegtam](https://github.com/vidforull/vegtam).
[GoReleaser](https://goreleaser.com) builds them from a tag, as
`.goreleaser.yaml` says, and the same commit builds the same bytes
anywhere ([Reproducible builds](#reproducible-builds)).
[DECISIONS.md](DECISIONS.md#2026-10-20-releases) says why GoReleaser.

## Verifying a download

`checksums.txt` lists the sum of each archive. For one archive:

```sh
awk '$2 == "vegtam_0.1.0_darwin_arm64.tar.gz"' checksums.txt | shasum -a 256 -c
```

`sha256sum -c` does the same on Linux. The sums are not signed: they
show that an archive is the one the sums were made for, not who made
either. The `Source code` archives that GitHub adds to each release are
made by GitHub from the tag, and `checksums.txt` does not cover them.

## Not signed, not notarized

The binaries are not signed with a developer certificate, nor notarized
by Apple. Go signs a binary for macOS on arm64 ad hoc, which Apple
silicon needs to run it at all, but Gatekeeper trusts no such signature.
A file downloaded with a browser carries the quarantine attribute, and
macOS refuses to run a binary unpacked from it. Once the archive's sum
is checked, remove the attribute before unpacking it:

```sh
xattr -d com.apple.quarantine vegtam_0.1.0_darwin_arm64.tar.gz
tar -xzf vegtam_0.1.0_darwin_arm64.tar.gz
```

A file fetched with curl gets no such attribute.

## Versions

Each version is tagged first as a release candidate, `vX.Y.Z-rc.N`, on
a commit of `main` that passes [Before a tag](#before-a-tag), and
published as a pre-release. Its archives, as the release offers them,
are then checked on macOS and Linux; a fix goes to `main` as any change
does, and makes the next candidate. The version, `vX.Y.Z`, is tagged
on the very commit of the candidate that passed, so that every check
holds for it. A pushed tag is never moved: Go's module proxy and
checksum database keep what a version held once anyone fetched it, so
a moved tag would give some people other code than others, or a
checksum error. A fix after a tag is the next candidate, or the next
patch version.

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
v2.18.3 (`go install github.com/goreleaser/goreleaser/v2@v2.18.3`):
another version may pack the archives otherwise, and their sums would
then differ, so `make release-check` refuses it. golangci-lint and
govulncheck at the versions the gate wants
([CONTRIBUTING.md](../CONTRIBUTING.md#tools)).

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
skip it.

### Tag and build

Tags are annotated, and made in UTC, as commits are: a candidate, or
the version on the commit of the candidate that passed, `rc.2` here.

```sh
TZ=UTC git tag -a v0.1.0-rc.1 -m 'vegtam 0.1.0-rc.1'
TZ=UTC git tag -a v0.1.0 -m 'vegtam 0.1.0' 'v0.1.0-rc.2^{commit}'
```

Build on the tag, with nothing changed:

```sh
git switch --detach v0.1.0-rc.1
export GOTOOLCHAIN=$(awk '$1 == "toolchain" {print $2}' go.mod)
GORELEASER_CURRENT_TAG=v0.1.0-rc.1 goreleaser release --clean
```

`GORELEASER_CURRENT_TAG` names the tag to build. The version shares its
commit with its last candidate, and GoReleaser, left to choose among
the tags of a commit, would build `v0.1.0` as `0.1.0-rc.2`.

`dist/` then holds `vegtam_<version>_<os>_<arch>.tar.gz` for each
target, with the binary, `LICENSE` and `README.md` in it,
`checksums.txt`, the binaries in a directory each, such as
`dist/vegtam_linux_amd64_v1/vegtam`, and GoReleaser's own metadata.
GoReleaser's release step is off: the output says `release is
disabled`, nothing is uploaded, and no token is needed. From a commit
that is not tagged, `goreleaser release --snapshot --clean` builds the
same set with a version that ends in `-SNAPSHOT-<commit>`, and
`goreleaser build --snapshot --clean` the binaries alone; a snapshot
builds a tree with changes too, and its binaries say `+dirty` after the
commit, while a release refuses such a tree.

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

Push the tag only once these checks pass, `git push origin v0.1.0-rc.1`;
until then `git tag -d v0.1.0-rc.1` still removes it.

### Publishing

GoReleaser publishes nothing. Once the tag is pushed, a maintainer
attaches the four archives and `checksums.txt` from `dist/`, and nothing
else from there, to a release of that tag on GitHub, titled
`vegtam 0.1.0-rc.1`; a candidate's release is marked as a pre-release.

## Reproducible builds

Two builds of one commit with the same Go and the same GoReleaser give
the same bytes, binaries and archives alike. Nothing in them depends on
when or where they were built: every time is the commit's (the date the
binary prints, its file time, the file times in the archive), paths are
trimmed, cgo is off, and the archives name root as the owner of each
file and fix its mode. `GOFLAGS` must not be set, since it could change
how the go command builds.

To check a release, build its tag again in a clone of your own, with the
tools above, and compare the sums with its `checksums.txt`. An empty
build cache makes the go command compile everything again rather than
reuse an earlier build:

```sh
dir=$(mktemp -d)
git clone --branch v0.1.0 https://github.com/vidforull/vegtam.git "$dir"
cd "$dir"
unset GOFLAGS
export GOTOOLCHAIN=$(awk '$1 == "toolchain" {print $2}' go.mod)
GORELEASER_CURRENT_TAG=v0.1.0 GOCACHE=$(mktemp -d) goreleaser release --clean
diff <the release's checksums.txt> dist/checksums.txt && echo same
```

The sums cover the archives, and with them the binaries.
