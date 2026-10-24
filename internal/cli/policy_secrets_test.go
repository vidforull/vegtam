package cli

import (
	"slices"
	"strings"
	"testing"
)

// TestPolicySecrets checks that vegtam policy lists the origins the
// policy binds secrets to, as text and as JSON, and refuses a policy
// that binds one to what is no origin.
func TestPolicySecrets(t *testing.T) {
	writePolicy(t, `{"secrets": {
  "env": {"API_TOKEN": ["https://API.example.com:443/", "http://127.0.0.1:8080"], "UNUSED": []},
  "cmd": {"TOKEN": ["https://auth.example.com:8443"]}
}}`)
	code, stdout, stderr := runCLI(t, true, "policy")
	var lines []string
	for line := range strings.Lines(stdout) {
		lines = append(lines, strings.Join(strings.Fields(line), " "))
	}
	want := []string{
		"secret {{$env API_TOKEN}} http://127.0.0.1:8080, https://api.example.com",
		"secret {{$env UNUSED}} bound to none: goes nowhere",
		"secret {{$cmd TOKEN}} https://auth.example.com:8443",
	}
	if i := slices.Index(lines, want[0]); code != exitOK || stderr != "" || i < 0 || !slices.Equal(lines[i:i+len(want)], want) {
		t.Errorf("policy = %d, %s\n%s\nwant the lines\n%s", code, stderr, stdout, strings.Join(want, "\n"))
	}

	code, stdout, _ = runCLI(t, false, "policy")
	var doc struct {
		Policy struct {
			Secrets []struct {
				Name    string
				Allowed []string
			}
		}
	}
	decode(t, stdout, &doc)
	var got []string
	for _, s := range doc.Policy.Secrets {
		got = append(got, s.Name+" "+strings.Join(s.Allowed, ","))
	}
	if want := []string{
		"{{$env API_TOKEN}} http://127.0.0.1:8080,https://api.example.com", "{{$env UNUSED}} ", "{{$cmd TOKEN}} https://auth.example.com:8443",
	}; code != exitOK || !slices.Equal(got, want) || !strings.Contains(stdout, `"name":"{{$env UNUSED}}","allowed":[]`) {
		t.Errorf("policy --json = %d, secrets %q\n%s", code, got, stdout)
	}
	validateJSON(t, stdout)

	// Without secrets, neither shows them; both say what a run without a
	// person does with secrets, the strict default.
	writePolicy(t, `{}`)
	if _, stdout, _ = runCLI(t, true, "policy"); strings.Contains(stdout, "secret {{") ||
		!strings.Contains(stdout, "It gets no secret value: a request that needs one is not sent") {
		t.Errorf("policy without secrets:\n%s", stdout)
	}
	if _, stdout, _ = runCLI(t, false, "policy"); strings.Contains(stdout, `"secrets":[`) ||
		!strings.Contains(stdout, `"secrets_mode":{"unattended":"deny","keeper_asks":"always"}`) || !strings.Contains(stdout, `"secrets":"none"`) {
		t.Errorf("policy --json without secrets:\n%s", stdout)
	}
	writePolicy(t, `{"secrets": {"unattended": "keeper", "keeper_asks": "unbound"}}`)
	if _, stdout, _ = runCLI(t, true, "policy"); !strings.Contains(stdout, "unattended   keeper\nkeeper asks  unbound\n") ||
		!strings.Contains(stdout, "goes through the keeper, which asks its person") {
		t.Errorf("policy with the keeper:\n%s", stdout)
	}
	if _, stdout, _ = runCLI(t, false, "policy"); !strings.Contains(stdout, `"secrets_mode":{"unattended":"keeper","keeper_asks":"unbound"}`) ||
		!strings.Contains(stdout, `"secrets":"keeper"`) {
		t.Errorf("policy --json with the keeper:\n%s", stdout)
	}
	validateJSON(t, stdout)

	writePolicy(t, `{"secrets": {"env": {"API_TOKEN": ["https://*.example.com"]}}}`)
	code, stdout, stderr = runCLI(t, false, "policy")
	if msg := `secrets.env.API_TOKEN: "https://*.example.com": a secret goes to origins named one by one; a wildcard names none`; code != exitPolicy ||
		!strings.Contains(stderr, msg) || !strings.Contains(stdout, `"kind":"policy"`) {
		t.Errorf("a wildcard = %d\n%s\n%s", code, stdout, stderr)
	}
}

// TestPolicySecretsHelp checks that the help of vegtam policy shows and
// says what secrets is.
func TestPolicySecretsHelp(t *testing.T) {
	_, stdout, _ := runCLI(t, true, "policy", "--help")
	for _, want := range []string{
		`"secrets": {"env": {"API_TOKEN": ["https://api.example.com"]},`,
		"secrets gives the values of {{$env NAME}} and {{$cmd NAME}}, by NAME,",
		"Nothing else binds them: they are the machine's",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help lacks %q\n%s", want, stdout)
		}
	}
}
