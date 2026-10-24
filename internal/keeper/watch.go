package keeper

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

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
		change := changeOf(base, path)
		if change == said {
			continue
		}
		said = change
		if change == "" {
			say("the policy's secrets are again those the keeper read at start.")
		} else {
			say(change)
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
