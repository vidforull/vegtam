package keeper

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/policy"
)

// Watch watches the policy file at path, of which start is what the
// keeper read when it started, and says through say when its secrets
// (secrets.env, secrets.cmd, secrets.unattended and secrets.keeper_asks)
// differ from those of start: what changed, once for each change. It
// looks at the file every interval, a second if it is not positive, and
// reads it again only once its size, its modification time or the file
// itself is new. It changes nothing that the keeper does: any process of
// the keeper's user, an agent's too, could write the file, and a policy
// that it wrote would bind a secret to wherever it liked; the person
// restarts the keeper to take a new one. It returns once ctx is done.
func Watch(ctx context.Context, path string, start *policy.Policy, interval time.Duration, say func(string)) {
	var base policy.Secrets
	if start != nil {
		base = start.Secrets
	}
	watch(ctx, path, interval, func() string { return changeOf(base, path) }, "the policy's secrets are again those the keeper read at start.", say)
}

// WatchTrust watches the file of the trust store of which start is what
// the keeper read when it started (see policy.Store.Snapshot), as Watch
// watches the policy, and says through say the command files that the
// file trusts and start does not, or no longer trusts, or trusts as they
// are now and not as they were. A trust given does not apply until the
// keeper starts again: a program of the keeper's user could trust any
// file of its own, and the keeper would run what it wrote. One taken
// back applies at once, as the snapshot asks the file too. It returns at
// once for a store with no file.
func WatchTrust(ctx context.Context, start *policy.Store, interval time.Duration, say func(string)) {
	path := start.Path()
	if path == "" {
		return
	}
	base, baseErr := start.List()
	watch(ctx, path, interval, func() string { return trustChangeOf(base, baseErr, path) }, "the trust store is again the one the keeper read at start.", say)
}

// watch looks at the file at path every interval, a second if it is not
// positive, and once its size, its modification time or the file itself
// is new, says through say what change says of it, escaped and on one
// line, once for each change; and again, when change says "" after
// something else. It returns once ctx is done.
func watch(ctx context.Context, path string, interval time.Duration, change func() string, again string, say func(string)) {
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	var (
		seen stamp  // of the file as it was last read; none at first, so that it is read once
		said string // the change said last; "" while there is none
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := stampOf(path)
		if now.same(seen) {
			continue
		}
		seen = now
		c := change()
		if c == said {
			continue
		}
		said = c
		if c == "" {
			say(again)
		} else {
			say(oneLine(c))
		}
	}
}

// stamp is what tells one state of a file from another.
type stamp struct {
	fi os.FileInfo // nil for no file
	ok bool        // set once the file has been looked at
}

// stampOf returns the stamp of the file at path as it is now.
func stampOf(path string) stamp {
	fi, err := os.Stat(path)
	if err != nil {
		return stamp{ok: true}
	}
	return stamp{fi: fi, ok: true}
}

// same reports whether s and o are of the same state of the file.
func (s stamp) same(o stamp) bool {
	switch {
	case !s.ok || !o.ok:
		return false
	case s.fi == nil || o.fi == nil:
		return s.fi == nil && o.fi == nil
	}
	return os.SameFile(s.fi, o.fi) && s.fi.Size() == o.fi.Size() && s.fi.ModTime().Equal(o.fi.ModTime())
}

// changeOf returns what the policy file at path says of secrets that
// start does not, as Watch says it; "" for nothing.
func changeOf(start policy.Secrets, path string) string {
	p, err := policy.LoadFile(path)
	if err != nil {
		return fmt.Sprintf("the policy cannot be read now: %v. The keeper keeps the policy it read at start.", err)
	}
	diffs := secretsDiff(start, p.Secrets)
	if len(diffs) == 0 {
		return ""
	}
	return "the policy changed: " + strings.Join(diffs, "; ") + ". The keeper keeps the policy it read at start: restart it to take the new one."
}

// maxTrustChanges is how many files a line of the keeper names: the rest
// it counts.
const maxTrustChanges = 8

// trustChangeOf returns what the trust store's file at path trusts that
// start, the files the keeper's store trusted when it started, or startErr,
// why it could not be read then, does not, as WatchTrust says it; "" for
// nothing.
func trustChangeOf(start map[string]string, startErr error, path string) string {
	now, err := policy.NewStore(path).List()
	switch {
	case err != nil && startErr != nil && err.Error() == startErr.Error():
		return ""
	case err != nil:
		return fmt.Sprintf("the trust store cannot be read now: %v. The keeper runs no command while it cannot.", err)
	}
	files := slices.Concat(slices.Collect(maps.Keys(start)), slices.Collect(maps.Keys(now)))
	slices.Sort(files)
	var diffs []string
	for _, file := range slices.Compact(files) {
		was, ok := start[file]
		sum, trusted := now[file]
		switch {
		case !ok:
			diffs = append(diffs, shownPath(file)+" trusted")
		case !trusted:
			diffs = append(diffs, shownPath(file)+" no longer trusted")
		case sum != was:
			diffs = append(diffs, shownPath(file)+" trusted as it is now")
		}
	}
	if len(diffs) == 0 {
		return ""
	}
	return "the trust store changed: " + some(diffs, "; ") + ". A trust taken back applies now; one given, once the keeper starts again."
}

// TrustedFiles returns the line that says which command files start, a
// snapshot of the trust store, trusts, whose commands the keeper may run;
// "" for none, or a store that could not be read.
func TrustedFiles(start *policy.Store) string {
	m, err := start.List()
	if err != nil || len(m) == 0 {
		return ""
	}
	var files []string
	for _, file := range slices.Sorted(maps.Keys(m)) {
		files = append(files, shownPath(file))
	}
	what := fmt.Sprintf("%d command files", len(files))
	if len(files) == 1 {
		what = "1 command file"
	}
	return oneLine("vegtam keeper: the commands it may run, once you type a code, are those of " + what + " trusted now: " + some(files, ", ") + ".")
}

// some joins the first maxTrustChanges of items with sep, and counts the
// rest.
func some(items []string, sep string) string {
	if n := len(items); n > maxTrustChanges {
		items = append(items[:maxTrustChanges:maxTrustChanges], fmt.Sprintf("and %d more", n-maxTrustChanges))
	}
	return strings.Join(items, sep)
}

// maxShownPath is the most bytes of a path that the keeper shows: a
// program may have written it, to fill the screen.
const maxShownPath = 256

// shownPath returns path as the keeper shows it: quoted as a shell would
// read it, cut short, at the start of a character, with "..." after.
func shownPath(path string) string {
	if len(path) <= maxShownPath {
		return core.ShellQuote(path)
	}
	n := maxShownPath
	for n > 0 && !utf8.RuneStart(path[n]) {
		n--
	}
	return core.ShellQuote(path[:n]) + "..."
}

// secretsDiff returns how b differs from a, one entry for each name or
// field: "secrets.env.API_TOKEN: [https://a] -> [https://a, https://b]".
func secretsDiff(a, b policy.Secrets) []string {
	var diffs []string
	for _, f := range []struct {
		name string
		a, b map[string][]string
	}{{"env", a.Env, b.Env}, {"cmd", a.Cmd, b.Cmd}} {
		names := slices.Sorted(maps.Keys(f.a))
		names = append(names, slices.Sorted(maps.Keys(f.b))...)
		slices.Sort(names)
		for _, name := range slices.Compact(names) {
			va, oka := f.a[name]
			vb, okb := f.b[name]
			if oka != okb || !slices.Equal(va, vb) {
				diffs = append(diffs, fmt.Sprintf("secrets.%s.%s: %s -> %s", f.name, name, origins(va, oka), origins(vb, okb)))
			}
		}
	}
	for _, f := range []struct{ name, a, b string }{
		{"unattended", a.Unattended, b.Unattended},
		{"keeper_asks", a.KeeperAsks, b.KeeperAsks},
	} {
		if f.a != f.b {
			diffs = append(diffs, fmt.Sprintf("secrets.%s: %s -> %s", f.name, setting(f.a), setting(f.b)))
		}
	}
	return diffs
}

// origins returns list as secretsDiff writes it; "not set" if ok is not.
func origins(list []string, ok bool) string {
	if !ok {
		return "not set"
	}
	return "[" + strings.Join(list, ", ") + "]"
}

// setting returns s, a setting of the policy, as secretsDiff writes it.
func setting(s string) string {
	if s == "" {
		return "not set"
	}
	return fmt.Sprintf("%q", s)
}
