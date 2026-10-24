package cli

import (
	"strings"
	"testing"
)

// TestCookieOutput signs in and sends the session cookie, and checks what
// the output says of the cookies: their names, never their values, and
// that --no-cookies keeps none. A person sees the attributes of each
// Set-Cookie; a run without a person, none of it.
func TestCookieOutput(t *testing.T) {
	fx := newFixture(t)
	file := fx.cookieFile(t)
	code, stdout, stderr := runCLI(t, true, "run", file, "-e", "test", "-v", "--confirm")
	if code != exitOK || !strings.Contains(stdout, "Set-Cookie: ***\nSet-Cookie: ***\n") ||
		!strings.Contains(stdout, "redacted (no person at a terminal): header Set-Cookie\n") || !strings.Contains(stdout, "X-Cookie: ***\n") {
		t.Errorf("without a person = %d\n%s\n%s", code, stdout, stderr)
	}
	code, stdout, stderr = runAt(t, "run", file, "-e", "test", "-v", "--confirm")
	for _, want := range []string{
		"Set-Cookie: session=***; Path=/; HttpOnly\nSet-Cookie: lang=***; Path=/\n",
		"* cookies: set session, lang\n",
		"* cookies: sent session, lang\n",
		"X-Cookie: session=***; lang=en\n", // a short value is no credential
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("--verbose lacks %q\nstdout: %s\nstderr: %s", want, stdout, stderr)
		}
	}
	if code != exitOK {
		t.Errorf("exit code %d", code)
	}
	code, stdout, _ = runCLI(t, false, "run", file, "-e", "test", "--confirm")
	validateJSON(t, stdout)
	for _, want := range []string{
		`"cookies":{"set":[{"hop":0,"name":"session","domain":"127.0.0.1","path":"/","host_only":true,"secure":false,"http_only":true,"stored":true},`,
		`"cookies":{"sent":[{"hop":0,"name":"session","domain":"127.0.0.1","path":"/","host_only":true,"secure":false,"http_only":true},`,
	} {
		if code != exitOK || !strings.Contains(stdout, want) {
			t.Errorf("JSON lacks %s\n%s", want, stdout)
		}
	}
	_, stdout, _ = runCLI(t, false, "run", file, "-e", "test", "--no-cookies", "--confirm")
	if !strings.Contains(stdout, `"reason":"the jar is off: --no-cookies"`) || strings.Contains(stdout, `"sent"`) || !strings.Contains(stdout, `"body":"{\"cookie\": \"\"}"`) {
		t.Errorf("--no-cookies:\n%s", stdout)
	}
}
