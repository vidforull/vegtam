package keeper

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/vidforull/vegtam/internal/core/policy"
)

func TestWatch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil { // whatever the umask
			t.Fatal(err)
		}
		path := filepath.Join(dir, policy.PolicyFile)
		write := func(s string) {
			t.Helper()
			// As an editor saves: a new file in the old one's place.
			tmp := path + ".new"
			if err := os.WriteFile(tmp, []byte(s), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, path); err != nil {
				t.Fatal(err)
			}
		}
		const atStart = `{"secrets": {"env": {"API_TOKEN": ["https://a.example"]}, "cmd": {"OLD": ["https://a.example"]}, "unattended": "keeper"}}`
		write(atStart)
		start, err := policy.LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var (
			mu   sync.Mutex
			said []string
		)
		ctx, cancel := context.WithCancel(t.Context())
		var wg sync.WaitGroup
		wg.Go(func() {
			Watch(ctx, path, start, time.Second, func(s string) {
				mu.Lock()
				defer mu.Unlock()
				said = append(said, s)
			})
		})
		// next lets a second go by, and returns what was said in it.
		next := func() []string {
			time.Sleep(time.Second)
			synctest.Wait()
			mu.Lock()
			defer mu.Unlock()
			s := said
			said = nil
			return s
		}
		if s := next(); len(s) != 0 {
			t.Errorf("said %q of the policy as at start", s)
		}
		write(`{"secrets": {"env": {"API_TOKEN": ["https://b.example", "https://a.example"], "NEW": []}, "unattended": "deny", "keeper_asks": "unbound"}}`)
		want := "the policy changed: " +
			"secrets.env.API_TOKEN: [https://a.example] -> [https://a.example, https://b.example]; " +
			"secrets.env.NEW: not set -> []; " +
			"secrets.cmd.OLD: [https://a.example] -> not set; " +
			`secrets.unattended: "keeper" -> "deny"; ` +
			`secrets.keeper_asks: not set -> "unbound". ` +
			"The keeper keeps the policy it read at start: restart it to take the new one."
		if s := next(); !slices.Equal(s, []string{want}) {
			t.Errorf("said %q, want %q", s, want)
		}
		if s := next(); len(s) != 0 {
			t.Errorf("said %q again", s)
		}
		// Written again as it is, or with other parts changed: nothing new.
		write(`{"limits": {"max_time_ceiling": "30s"}, "secrets": {"env": {"API_TOKEN": ["https://b.example", "https://a.example"], "NEW": []}, "unattended": "deny", "keeper_asks": "unbound"}}`)
		if s := next(); len(s) != 0 {
			t.Errorf("said %q of the same secrets", s)
		}
		write(`{"secrets": `)
		if s := next(); len(s) != 1 || !strings.HasPrefix(s[0], "the policy cannot be read now: ") || !strings.HasSuffix(s[0], "The keeper keeps the policy it read at start.") {
			t.Errorf("said %q of a policy that does not parse", s)
		}
		write(atStart)
		if s := next(); !slices.Equal(s, []string{"the policy's secrets are again those the keeper read at start."}) {
			t.Errorf("said %q of the policy as at start again", s)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if s := next(); len(s) != 1 || !strings.Contains(s[0], "secrets.env.API_TOKEN: [https://a.example] -> not set") {
			t.Errorf("said %q of a policy that is gone", s)
		}
		cancel()
		wg.Wait()
		// What the keeper uses is what it read.
		if got := start.Secrets.Env["API_TOKEN"]; !slices.Equal(got, []string{"https://a.example"}) {
			t.Errorf("the policy at start is now %q", got)
		}
	})
}
