package keeper

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// fuzzLine is the limit of a line in FuzzDecode, far below MaxLine, so
// that inputs reach it.
const fuzzLine = 1 << 10

// FuzzDecode feeds the decoders of both sides lines that neither wrote:
// none panics; no line read holds more than the limit; and a message
// decoded encodes to a line that decodes to the same message, which
// encodes to the same line. The first encoding may differ from the line
// read, and its message from the first: fields that a side does not know
// are dropped, and so are empty lists that it leaves out.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		`{"keeper":1,"pid":4242}`,
		`{"keeper":1}`,
		`{"keeper":2,"pid":1}`,
		`{"error":{"kind":"policy","message":"no"}}`,
		`{"id":1,"send":{"ref":"a.http#1","env":"dev","request":{"method":"GET","url":"https://{{host}}/","source":{"file":"a.http","line":1}},` +
			`"method":"GET","url":[{"text":"https://"},{"secret":{"name":"host"}},{"text":"/"}],"headers":[{"name":"Authorization","value":[{"text":"Bearer "},{"secret":{"name":"$env TOKEN"}}]}],` +
			`"body":[],"max_body":1024,"fail":true,"captured":[{"name":"sid","secret":true,"value":"v","origins":["https://a.example"]}]}}`,
		`{"id":1,"inbound":{"result":{"ref":"a.http#1","response":{"proto":"HTTP/1.1","status":200,"reason":"OK","headers":[],"body":"{}","truncated":false,"untrusted":true,"tls_verified":true},` +
			`"timing":{"total_ms":1.5,"connect_ms":0.25},"redacted":["header Set-Cookie"],"error":{"kind":"assert","message":"x"}},"captured":[{"name":"id","value":"7"}]}}`,
		`{"id":2,"error":{"kind":"network","message":"refused"}}`,
		`{"id":1,"inbound":{"result":{}},"captured":[]}`,
		`{"id":1,"inbound":{"result":{"captures":[]}}}` + "\n" + `{"id":2,"send":{}}`,
		"not json\n{\"id\":",
		strings.Repeat("a", fuzzLine+1),
		`{"keeper":1e3}`,
		`{"id":9223372036854775807,"send":{"max_body":-1}}`,
		"\x00\xff\n\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r := newLineReader(bytes.NewReader(b), fuzzLine)
		for {
			line, err := r.next()
			if err != nil {
				if _, long := errors.AsType[*tooLongError](err); long && len(b) <= fuzzLine {
					t.Fatalf("a line too long in %d bytes", len(b))
				}
				return
			}
			if len(line) > fuzzLine || cap(line) > fuzzLine+1 {
				t.Fatalf("a line of %d bytes, %d held, past the limit of %d", len(line), cap(line), fuzzLine)
			}
			roundTrip(t, line, decodeKeeperHello)
			roundTrip(t, line, decodeRunHello)
			roundTrip(t, line, decodeRequest)
			roundTrip(t, line, decodeReply)
		}
	})
}

// roundTrip checks that what decode makes of line, if anything, encodes
// to a line that decodes to the same message, which encodes to the same
// line.
func roundTrip[M any](t *testing.T, line []byte, decode func([]byte) (M, error)) {
	t.Helper()
	m, err := decode(line)
	if err != nil {
		return
	}
	b1, err := encode(m)
	if err != nil {
		t.Fatalf("%s decodes, but does not encode: %v", line, err)
	}
	m2, err := decode(bytes.TrimSuffix(b1, []byte("\n")))
	if err != nil {
		t.Fatalf("%s decodes, but its encoding %s does not: %v", line, b1, err)
	}
	b2, err := encode(m2)
	if err != nil || !bytes.Equal(b1, b2) {
		t.Fatalf("%s encodes to %s, then to %s (%v)", line, b1, b2, err)
	}
	m3, err := decode(bytes.TrimSuffix(b2, []byte("\n")))
	if err != nil || !reflect.DeepEqual(m2, m3) {
		t.Fatalf("%s: %+v decodes again to %+v (%v)", line, m2, m3, err)
	}
}
