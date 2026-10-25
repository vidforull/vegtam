package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// TestCanceled cancels a run as Ctrl-C does, while a request waits for
// its response and while a {{$cmd NAME}} runs: vegtam stops, exits with
// 130, and prints the error masked.
func TestCanceled(t *testing.T) {
	fx := newFixture(t) // with a configuration directory of its own: no file is trusted yet
	t.Setenv("VEGTAM_TEST_HELPER", "1")
	t.Setenv("GORACE", "atexit_sleep_ms=0") // a helper built with -race would wait a second
	cmds, _ := json.Marshal(map[string]any{
		"KEY":  map[string]any{"argv": []string{os.Args[0], "-test.run=^TestHelperProcess$"}},
		"SLOW": map[string]any{"argv": []string{os.Args[0], "-test.run=^TestHelperProcess$", "--", "sleep"}},
	})
	if err := os.Mkdir(fx.path("cmd"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"cmd/http-client.cmd.json": string(cmds),
		"cmd/slow.http":            "GET {{host}}/echo?key={{token}}&cmd={{$cmd KEY}}&slow={{$cmd SLOW}}\n",
	}
	for name, src := range files {
		if err := os.WriteFile(fx.path(name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code, _, stderr := runAt(t, "trust", fx.path("cmd")); code != exitOK {
		t.Fatalf("trust = %d: %s", code, stderr)
	}
	for _, tt := range []struct {
		name string
		args []string
	}{
		{"request", []string{"run", fx.path("api.http") + "#slow", "-e", "test"}},
		{"command", []string{"run", fx.path("cmd/slow.http") + "#1", "-e", "test"}},
	} {
		for _, tty := range []bool{true, false} {
			ctx, cancel := context.WithCancel(t.Context())
			timer := time.AfterFunc(100*time.Millisecond, cancel)
			var stdout, stderr bytes.Buffer
			start := time.Now()
			code := Run(ctx, tt.args, Config{Stdout: &stdout, Stderr: &stderr, TTY: tty, local: testKeeper})
			timer.Stop()
			cancel()
			if code != exitCanceled || !strings.Contains(stderr.String(), "context canceled") {
				t.Errorf("%s (tty %v) = %d, stderr %q; want %d and the cancellation", tt.name, tty, code, stderr.String(), exitCanceled)
			}
			if d := time.Since(start); d > 30*time.Second {
				t.Errorf("%s returned after %s", tt.name, d)
			}
			if !tty {
				validateJSON(t, stdout.String())
				if !strings.Contains(stdout.String(), `"kind":"canceled"`) {
					t.Errorf("%s: stdout = %s, want an error of kind canceled", tt.name, stdout.String())
				}
			}
			all := stdout.String() + stderr.String()
			if found := append(fx.leaks(all), cmdLeaks(all)...); len(found) > 0 {
				t.Errorf("%s: secret forms %q in\n%s", tt.name, found, all)
			}
		}
	}
}

// cmdLeaks returns the forms of cmdSecret that s contains.
func cmdLeaks(s string) []string {
	var found []string
	for _, f := range []string{cmdSecret, cmdSecret[:4], strings.ReplaceAll(cmdSecret, "/", `\/`)} {
		if strings.Contains(s, f) {
			found = append(found, f)
		}
	}
	return found
}
