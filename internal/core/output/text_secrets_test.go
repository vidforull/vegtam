package output

import (
	"strings"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
)

// TestWriteSecrets checks the text form of where the secrets of a request
// may go: one a line, the names aligned, and each kind of binding.
func TestWriteSecrets(t *testing.T) {
	secrets := []Secret{
		{Name: "{{token}}", Origin: "https://api.example.com", Allowed: []string{"https://api.example.com"}},
		{Name: "{{$env TOKEN}}", Origin: "https://api.example.com", Allowed: []string{}},
		{Name: "{{session}}", Origin: "https://api.example.com", Allowed: []string{"https://login.example.com"}, Captured: true},
		{Name: "{{next}}", Allowed: []string{}, Captured: true},
		{Name: "{{key}}", Allowed: []string{"https://a.example", "https://b.example"}},
	}
	var b strings.Builder
	b.WriteString("GET https://api.example.com/\n")
	WriteSecrets(&b, secrets)
	want := `GET https://api.example.com/

Secrets:
  {{token}}       https://api.example.com
  {{$env TOKEN}}  bound to no origin; refused for https://api.example.com
  {{session}}     captured from https://login.example.com; refused for https://api.example.com
  {{next}}        captured from an origin that is not known
  {{key}}         https://a.example, https://b.example
`
	if b.String() != want {
		t.Errorf("WriteSecrets:\n%s\nwant:\n%s", b.String(), want)
	}
	var none strings.Builder
	if WriteSecrets(&none, nil); none.Len() != 0 {
		t.Errorf("no secrets: %q", none.String())
	}
}

// TestSecretWhy checks what is said of a secret that may not go where its
// request goes, of each kind.
func TestSecretWhy(t *testing.T) {
	to := "https://exfil.example"
	for _, tt := range []struct {
		s    Secret
		want string
	}{
		{Secret{Name: "{{token}}", Origin: to, Allowed: []string{}}, "{{token}} goes to https://exfil.example, but it is bound to no origin"},
		{
			Secret{Name: "{{token}}", Origin: to, Allowed: []string{"https://a.example", "https://b.example"}},
			"{{token}} goes to https://exfil.example, but it may go only to https://a.example, https://b.example",
		},
		{
			Secret{Name: "{{session}}", Origin: to, Allowed: []string{"https://login.example.com"}, Captured: true},
			"{{session}} goes to https://exfil.example, but it came from a response of https://login.example.com and may go back only there",
		},
		{
			Secret{Name: "{{session}}", Origin: to, Allowed: []string{}, Captured: true},
			"{{session}} goes to https://exfil.example, but it came from a response whose origin is not known",
		},
	} {
		if got := SecretWhy(tt.s); got != tt.want {
			t.Errorf("SecretWhy(%+v) = %q, want %q", tt.s, got, tt.want)
		}
		if !tt.s.Refused() {
			t.Errorf("%+v is not refused", tt.s)
		}
	}
	if (Secret{Name: "{{token}}", Allowed: []string{}}).Refused() {
		t.Error("a secret whose request goes where is not known yet is refused")
	}
}

// TestWriteConfirm checks the line of a dry run that says what sending
// the request would need, for each reason.
func TestWriteConfirm(t *testing.T) {
	note, empty := "Deletes \x1b[2J everything", ""
	secret := &Secret{Name: "{{token}}", Origin: "https://exfil.example", Allowed: []string{}}
	why := "{{token}} goes to https://exfil.example, but it is bound to no origin"
	for _, tt := range []struct {
		c    *Confirm
		want string
	}{
		{nil, ""},
		{
			&Confirm{Reason: core.ReasonMethod, Flag: "--confirm=api.http#create"},
			"sending it needs --confirm=api.http#create: its method is not GET, HEAD or OPTIONS, and no person is at a terminal\n",
		},
		{&Confirm{Reason: core.ReasonNote, Note: &empty, Flag: "--confirm=api.http#2"}, "sending it needs --confirm=api.http#2: its @note asks for a person\n"},
		{
			&Confirm{Reason: core.ReasonNote, Note: &note, Flag: "--confirm=api.http#2", Secret: secret},
			"sending it needs --confirm=api.http#2: " + why + "; its @note asks for a person: " + note + "\n",
		},
		{&Confirm{Reason: core.ReasonSecret, Flag: "--confirm=api.http#1", Secret: secret}, "sending it needs --confirm=api.http#1: " + why + "\n"},
	} {
		var b strings.Builder
		if WriteConfirm(&b, tt.c); b.String() != tt.want {
			t.Errorf("WriteConfirm(%+v) = %q, want %q", tt.c, b.String(), tt.want)
		}
	}
}
