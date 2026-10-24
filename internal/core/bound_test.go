package core

import (
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// boundSecrets are the secrets of the tests of where secrets go: each
// value is "v-" and its name, and bindings says where each may go.
type boundSecrets struct {
	bindings map[string][]string // by name, as a person may write them: unsorted, twice
	late     []string            // the names known only when the request is sent
	values   map[string]string   // the values that are not "v-" and the name
}

func (b boundSecrets) SecretValue(s Secret) (string, error) {
	switch v, ok := b.values[s.Name]; {
	case slices.Contains(b.late, s.Name):
		return "", ErrLate
	case ok:
		return v, nil
	}
	return "v-" + s.Name, nil
}

func (b boundSecrets) SecretOrigins(s Secret) []string { return b.bindings[s.Name] }

func boundRef(name string) Segment     { return Segment{Secret: &Secret{Name: name}} }
func boundCapture(name string) Segment { return Segment{Secret: &Secret{Name: name, Capture: true}} }

// TestBoundBindings checks that each secret of the texts comes once, in
// the order they hold them, with its origins sorted and each once, and
// that a request goes where its secrets are bound only.
func TestBoundBindings(t *testing.T) {
	src := boundSecrets{bindings: map[string][]string{
		"token":    {"https://b.example", "https://api.example.com", "https://b.example"},
		"$env KEY": {"https://api.example.com"},
		"session":  {"https://login.example"},
	}}
	url := Text{{Text: "https://api.example.com/?t="}, boundRef("token")}
	header := Text{{Text: "Bearer "}, boundRef("token"), {Text: " "}, boundRef("$env KEY")}
	body := Text{{Text: `{"s": "`}, boundCapture("session"), {Text: `", "n": "`}, boundRef("none"), {Text: `"}`}}

	got := Bindings(src, "https://api.example.com", url, header, body)
	want := []Bound{
		{Name: "{{token}}", Origin: "https://api.example.com", Allowed: []string{"https://api.example.com", "https://b.example"}},
		{Name: "{{$env KEY}}", Origin: "https://api.example.com", Allowed: []string{"https://api.example.com"}},
		{Name: "{{session}}", Origin: "https://api.example.com", Allowed: []string{"https://login.example"}, Capture: true},
		{Name: "{{none}}", Origin: "https://api.example.com"},
	}
	if !slices.EqualFunc(got, want, equalBound) {
		t.Fatalf("Bindings =\n%+v\nwant\n%+v", got, want)
	}
	refused := Refused(got)
	if names := boundNames(refused); !slices.Equal(names, []string{"{{session}}", "{{none}}"}) {
		t.Errorf("Refused = %q", names)
	}
	// Refused leaves its argument be.
	if !slices.EqualFunc(got, want, equalBound) {
		t.Errorf("Refused changed its argument: %+v", got)
	}
	if got[0].Refused() || got[1].Refused() || !got[2].Refused() || !got[3].Refused() {
		t.Errorf("Refused() of %+v", got)
	}
	// The order of the request: URL, headers, body.
	p := &Prepared{URL: url, Headers: []PreparedHeader{{Name: "Authorization", Value: header}}, Body: body}
	if texts := p.Texts(); len(texts) != 3 || texts[0].Masked() != url.Masked() || texts[1].Masked() != header.Masked() || texts[2].Masked() != body.Masked() {
		t.Errorf("Texts = %v", texts)
	}
	if names := boundNames(Unbound(p, src, "https://b.example")); !slices.Equal(names, []string{"{{$env KEY}}", "{{session}}", "{{none}}"}) {
		t.Errorf("Unbound to https://b.example = %q", names)
	}
	if names := boundNames(Unbound(&Prepared{URL: url}, src, "https://b.example")); len(names) != 0 {
		t.Errorf("Unbound of a token that may go there = %q", names)
	}
	// Where a request goes that is not known yet, nothing is refused yet.
	for _, b := range Bindings(src, "", url, header, body) {
		if b.Origin != "" || b.Refused() {
			t.Errorf("an unknown origin: %+v", b)
		}
	}
	if none := Bindings(src, "https://api.example.com", Text{{Text: "no secret"}}, nil); none != nil {
		t.Errorf("Bindings of no secret = %+v", none)
	}
	// What Bindings returns is its own: the source's origins stay as they
	// were.
	got[0].Allowed[0] = "https://changed.example"
	if src.bindings["token"][0] != "https://b.example" {
		t.Errorf("the source's origins changed: %q", src.bindings["token"])
	}
}

func equalBound(a, b Bound) bool {
	return a.Name == b.Name && a.Origin == b.Origin && slices.Equal(a.Allowed, b.Allowed) && a.Capture == b.Capture
}

func boundNames(bs []Bound) []string {
	var names []string
	for _, b := range bs {
		names = append(names, b.Name)
	}
	return names
}

// TestBoundGrant checks that a person's confirmation lets every secret go
// to the origin confirmed, and there alone, without changing the source.
func TestBoundGrant(t *testing.T) {
	// A slice with room to spare: a grant that appended to it in place
	// would write over another grant's origin.
	spare := make([]string, 1, 4)
	spare[0] = "https://api.example.com"
	src := boundSecrets{bindings: map[string][]string{"token": spare}}
	a, b := Grant(src, "https://a.example"), Grant(src, "https://b.example")
	token := Secret{Name: "token"}
	if got := a.SecretOrigins(token); !slices.Equal(got, []string{"https://api.example.com", "https://a.example"}) {
		t.Errorf("granted a: %q", got)
	}
	if got := b.SecretOrigins(token); !slices.Equal(got, []string{"https://api.example.com", "https://b.example"}) {
		t.Errorf("granted b: %q", got)
	}
	if got := a.SecretOrigins(Secret{Name: "none"}); !slices.Equal(got, []string{"https://a.example"}) {
		t.Errorf("a secret bound to none, granted: %q", got)
	}
	if got := src.SecretOrigins(token); !slices.Equal(got, []string{"https://api.example.com"}) {
		t.Errorf("the source after the grants: %q", got)
	}
	// The values are the source's.
	if v, err := a.SecretValue(token); v != "v-token" || err != nil {
		t.Errorf("SecretValue of a grant = %q, %v", v, err)
	}
	p := &Prepared{URL: Text{{Text: "https://a.example/?t="}, boundRef("token"), {Text: "&n="}, boundRef("none")}}
	if refused := Unbound(p, a, "https://a.example"); len(refused) != 0 {
		t.Errorf("granted, to where it was granted: %+v", refused)
	}
	if names := boundNames(Unbound(p, a, "https://exfil.example")); !slices.Equal(names, []string{"{{token}}", "{{none}}"}) {
		t.Errorf("granted, elsewhere: %q", names)
	}
}

// TestBoundWhy checks what an error says of each kind of secret it
// refuses.
func TestBoundWhy(t *testing.T) {
	to := "https://exfil.example"
	bound := Bound{Name: "{{token}}", Origin: to, Allowed: []string{"https://api.example.com", "https://b.example"}}
	none := Bound{Name: "{{$env KEY}}", Origin: to}
	back := Bound{Name: "{{session}}", Origin: to, Allowed: []string{"https://login.example"}, Capture: true}
	lost := Bound{Name: "{{id}}", Origin: to, Capture: true}
	for _, tt := range []struct {
		refused []Bound
		want    string
	}{
		{[]Bound{bound}, "secret {{token}} may not go to https://exfil.example: its allowed origins are https://api.example.com, https://b.example"},
		{[]Bound{none}, "secret {{$env KEY}} may not go to https://exfil.example: it is bound to no origin"},
		{[]Bound{back}, "secret {{session}} may not go to https://exfil.example: it was captured from a response of https://login.example, and goes back there alone"},
		{[]Bound{lost}, "secret {{id}} may not go to https://exfil.example: it was captured from a response whose origin is not known, and goes nowhere"},
		{
			[]Bound{none, back, bound},
			"secret {{$env KEY}} may not go to https://exfil.example: it is bound to no origin; " +
				"nor may {{session}}: it was captured from a response of https://login.example, and goes back there alone; " +
				"nor may {{token}}: its allowed origins are https://api.example.com, https://b.example",
		},
	} {
		if got := Why(tt.refused); got != tt.want {
			t.Errorf("Why(%q) =\n%q\nwant\n%q", boundNames(tt.refused), got, tt.want)
		}
	}
}

// TestBoundSecretError checks the error of a request refused for its
// secrets: its kind, where it is, what it says, and the first secret.
func TestBoundSecretError(t *testing.T) {
	to := "https://exfil.example"
	none := Bound{Name: "{{token}}", Origin: to}
	back := Bound{Name: "{{session}}", Origin: to, Allowed: []string{"https://login.example"}, Capture: true}
	machine := Bound{Name: "{{$env KEY}}", Origin: to, Allowed: []string{"https://api.example.com"}}
	cmd := Bound{Name: "{{$cmd TOKEN}}", Origin: to}
	src := Source{File: "api.http", Line: 3}
	for _, tt := range []struct {
		kind    Kind
		what    string
		refused []Bound
		want    string
	}{
		{
			KindPolicy, "GET {{host}}/?t={{token}} is not sent",
			[]Bound{none},
			"GET {{host}}/?t={{token}} is not sent: secret {{token}} may not go to https://exfil.example: it is bound to no origin; " +
				"allow it in http-client.private.env.json ($allow)",
		},
		{
			KindConfirm, "",
			[]Bound{back},
			"secret {{session}} may not go to https://exfil.example: it was captured from a response of https://login.example, and goes back there alone",
		},
		// One that can be bound is enough for the hint to say where.
		{
			KindPolicy, "refused a redirect to https://exfil.example of a URL that holds a secret",
			[]Bound{back, none},
			"refused a redirect to https://exfil.example of a URL that holds a secret: secret {{session}} may not go to https://exfil.example: " +
				"it was captured from a response of https://login.example, and goes back there alone; nor may {{token}}: it is bound to no origin; " +
				"allow it in http-client.private.env.json ($allow)",
		},
		// The machine's values are bound in the policy alone.
		{
			KindPolicy, "",
			[]Bound{machine},
			"secret {{$env KEY}} may not go to https://exfil.example: its allowed origins are https://api.example.com; allow it in the policy (secrets)",
		},
		{
			KindConfirm, "",
			[]Bound{machine, back, none, cmd},
			"secret {{$env KEY}} may not go to https://exfil.example: its allowed origins are https://api.example.com; " +
				"nor may {{session}}: it was captured from a response of https://login.example, and goes back there alone; " +
				"nor may {{token}}: it is bound to no origin; nor may {{$cmd TOKEN}}: it is bound to no origin; " +
				"allow it in http-client.private.env.json ($allow), or for {{$env NAME}} and {{$cmd NAME}} in the policy (secrets)",
		},
	} {
		e := SecretError(tt.kind, src, tt.what, tt.refused)
		if e.Kind != tt.kind || e.Source != src || e.Msg != tt.want || e.Secret == nil || !equalBound(*e.Secret, tt.refused[0]) || e.Confirm != nil {
			t.Errorf("SecretError(%s, %q) = %+v, message\n%q\nwant\n%q", tt.kind, tt.what, e, e.Msg, tt.want)
		}
		if !strings.HasPrefix(e.Error(), "api.http:3: ") {
			t.Errorf("Error() = %q", e.Error())
		}
		if ce, ok := errors.AsType[*Error](error(e)); !ok || ce.Secret != e.Secret {
			t.Errorf("errors.AsType lost the secret: %+v", ce)
		}
	}
}

// TestBoundTextOrigin checks where a URL goes, its secrets revealed: a
// value known only when the request is sent is no matter after the host
// and port, and makes the origin unknown before them.
func TestBoundTextOrigin(t *testing.T) {
	src := boundSecrets{late: []string{"late"}, values: map[string]string{"base": "https://API.example.com:443/v1"}}
	for _, tt := range []struct {
		url   Text
		want  string
		known bool
	}{
		{Text{{Text: "https://api.example.com/?t="}, boundRef("token")}, "https://api.example.com", true},
		{Text{boundRef("base"), {Text: "/users"}}, "https://api.example.com", true},
		{Text{{Text: "http://127.0.0.1:8080/?t="}, boundRef("late")}, "http://127.0.0.1:8080", true},
		{Text{{Text: "https://api.example.com?t="}, boundRef("late")}, "https://api.example.com", true},
		{Text{{Text: "https://"}, boundRef("late"), {Text: "/x"}}, "", false},
		{Text{{Text: "https://api.example.com:"}, boundRef("late")}, "", false},
		{Text{boundRef("late"), {Text: "/x"}}, "", false},
		{Text{{Text: "ftp://example.com/"}, boundRef("token")}, "", false},
		{Text{{Text: "https://exa mple.com/"}}, "", false},
	} {
		got, known, err := tt.url.Origin(src)
		if got != tt.want || known != tt.known || err != nil {
			t.Errorf("Origin of %s = %q, %v, %v; want %q, %v", tt.url.Masked(), got, known, err, tt.want, tt.known)
		}
	}
	if _, _, err := (Text{{Text: "https://"}, boundRef("missing")}).Origin(secretMap{}); err == nil {
		t.Error("Origin with a secret that cannot be revealed: no error")
	}
}

// TestBoundOrigins checks where a request goes, by its URL and its Host
// header: the second origin is that of the header, over the URL's scheme,
// unless it names the same.
func TestBoundOrigins(t *testing.T) {
	u, err := url.Parse("https://api.example.com/x")
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string][]string{
		"":                     {"https://api.example.com"},
		"API.example.com":      {"https://api.example.com"},
		"api.example.com:443":  {"https://api.example.com"},
		"api.example.com.":     {"https://api.example.com"},
		"cdn.example":          {"https://api.example.com", "https://cdn.example"},
		"api.example.com:8443": {"https://api.example.com", "https://api.example.com:8443"},
	} {
		if got := Origins(u, host); !slices.Equal(got, want) {
			t.Errorf("Origins(%s, %q) = %q, want %q", u, host, got, want)
		}
	}
	host := func(v Text) PreparedHeader { return PreparedHeader{Name: "host", Value: v} }
	src := lateSecrets{secretMap{"token": "t0k", "front": "cdn.example"}, []string{"late"}}
	for _, tt := range []struct {
		name    string
		p       *Prepared
		want    []string
		known   bool
		wantErr bool
	}{
		{"no Host", &Prepared{URL: Text{{Text: "https://api.example.com/?t="}, {Secret: &Secret{Name: "token"}}}}, []string{"https://api.example.com"}, true, false},
		{
			"a secret Host", &Prepared{URL: Text{{Text: "https://api.example.com/"}}, Headers: []PreparedHeader{host(Text{{Secret: &Secret{Name: "front"}}})}},
			[]string{"https://api.example.com", "https://cdn.example"},
			true, false,
		},
		{
			"the last Host", &Prepared{URL: Text{{Text: "https://api.example.com/"}}, Headers: []PreparedHeader{host(Text{{Text: "cdn.example"}}), host(Text{{Text: "api.example.com"}})}},
			[]string{"https://api.example.com"},
			true, false,
		},
		{"a late Host", &Prepared{URL: Text{{Text: "https://api.example.com/"}}, Headers: []PreparedHeader{host(Text{{Secret: &Secret{Name: "late"}}})}}, nil, false, false},
		{"a Host that is not there", &Prepared{URL: Text{{Text: "https://api.example.com/"}}, Headers: []PreparedHeader{host(Text{{Secret: &Secret{Name: "none"}}})}}, nil, false, true},
	} {
		got, known, err := tt.p.Origins(src)
		if !slices.Equal(got, tt.want) || known != tt.known || (err != nil) != tt.wantErr {
			t.Errorf("%s: Origins = %q, %v, %v", tt.name, got, known, err)
		}
	}
}
