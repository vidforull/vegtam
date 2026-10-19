package cli

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func runCLI(t *testing.T, tty bool, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(t.Context(), args, Config{Stdout: &out, Stderr: &errOut, TTY: tty, Version: "v1.2.3"})
	return code, out.String(), errOut.String()
}

func TestVersion(t *testing.T) {
	build := runtime.Version() + `","os":"` + runtime.GOOS + `","arch":"` + runtime.GOARCH
	tests := []struct {
		name string
		tty  bool
		args []string
		want string
	}{
		{
			"terminal", true,
			[]string{"version"},
			"vegtam v1.2.3 (" + runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH + ")\n",
		},
		{
			"not a terminal", false,
			[]string{"version"},
			`{"name":"vegtam","version":"v1.2.3","go":"` + build + `"}` + "\n",
		},
		{
			"--json on a terminal", true,
			[]string{"version", "--json"},
			"{\n  \"name\": \"vegtam\",\n  \"version\": \"v1.2.3\",\n  \"go\": \"" + runtime.Version() +
				"\",\n  \"os\": \"" + runtime.GOOS + "\",\n  \"arch\": \"" + runtime.GOARCH + "\"\n}\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, tt.tty, tt.args...)
			if code != exitOK || stdout != tt.want || stderr != "" {
				t.Errorf("%v = %d, %q, %q; want %d, %q, empty stderr", tt.args, code, stdout, stderr, exitOK, tt.want)
			}
		})
	}
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"-h"}, {"--help"}, {"version", "-h"}, {"help", "version"}} {
		code, stdout, stderr := runCLI(t, false, args...)
		if code != exitOK || !strings.Contains(stdout, "Usage:") || stderr != "" {
			t.Errorf("%q = %d, %q, %q; want %d, help on stdout, empty stderr", args, code, stdout, stderr, exitOK)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"frobnicate"}, `vegtam: unknown command "frobnicate" for "vegtam"`},
		{[]string{"--bogus"}, "vegtam: unknown flag: --bogus"},
		{[]string{"version", "--bogus"}, "vegtam: unknown flag: --bogus"},
		{[]string{"version", "extra"}, `vegtam: unknown command "extra" for "vegtam version"`},
	}
	for _, tt := range tests {
		// Not on a terminal, the error is also a JSON document on stdout.
		msg, _ := json.Marshal(strings.TrimPrefix(tt.want, "vegtam: "))
		for tty, wantOut := range map[bool]string{true: "", false: `{"schema_version":1,"error":{"kind":"usage","message":` + string(msg) + "}}\n"} {
			code, stdout, stderr := runCLI(t, tty, tt.args...)
			if code != exitUsage || stdout != wantOut || !strings.HasPrefix(stderr, tt.want+"\n") {
				t.Errorf("%q (tty %v) = %d, %q, %q; want %d, stdout %q, stderr starting with %q",
					tt.args, tty, code, stdout, stderr, exitUsage, wantOut, tt.want)
			}
		}
	}
}
