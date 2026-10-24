package keeper

import (
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/vidforull/vegtam/internal/core"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

func TestLineReader(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    string
		lines []string
		err   string // of the read after the lines
	}{
		{"lines", "a\nbb\n\n", []string{"a", "bb", ""}, "EOF"},
		{"none", "", nil, "EOF"},
		{"at the limit", "12345678\n", []string{"12345678"}, "EOF"},
		{"over the limit", "123456789\n", nil, "a line longer than 8 bytes"},
		{"over the limit, no newline", "123456789", nil, "a line longer than 8 bytes"},
		{"truncated", "a\nbc", []string{"a"}, "unexpected EOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newLineReader(strings.NewReader(tc.in), 8)
			var lines []string
			for {
				line, err := r.next()
				if err != nil {
					if err.Error() != tc.err {
						t.Errorf("error %q, want %q", err, tc.err)
					}
					break
				}
				lines = append(lines, string(line))
			}
			if strings.Join(lines, "|") != strings.Join(tc.lines, "|") || len(lines) != len(tc.lines) {
				t.Errorf("lines %q, want %q", lines, tc.lines)
			}
		})
	}
}

// endless is a stream with no newline that never ends.
type endless struct{}

func (endless) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 'a'
	}
	return len(b), nil
}

func TestLineReaderBounded(t *testing.T) {
	const limit = 4 << 20
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := newLineReader(endless{}, limit).next()
	runtime.ReadMemStats(&after)
	if _, ok := errors.AsType[*tooLongError](err); !ok {
		t.Fatalf("error %v, want a line too long", err)
	}
	// What the line holds, its buffer, and what growing it to the limit
	// leaves behind: no more.
	if n := after.TotalAlloc - before.TotalAlloc; n > 3*limit {
		t.Errorf("%d bytes allocated for a line of at most %d", n, limit)
	}
}

func TestEncode(t *testing.T) {
	b, err := encode(reply{ID: 3, Error: &wireError{Kind: core.KindPolicy, Message: "<no> & more"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"id":3,"error":{"kind":"policy","message":"<no> & more"}}` + "\n"; string(b) != want {
		t.Errorf("%s, want %s", b, want)
	}
	_, err = encode(reply{ID: 1, Error: &wireError{Kind: core.KindPolicy, Message: strings.Repeat("a", MaxLine)}})
	if _, ok := errors.AsType[*tooLongError](err); !ok {
		t.Errorf("a line over the limit: %v", err)
	}
}

func TestDecode(t *testing.T) {
	type decoder func([]byte) error
	keeperHello := func(b []byte) error { _, err := decodeKeeperHello(b); return err }
	runHello := func(b []byte) error { _, err := decodeRunHello(b); return err }
	req := func(b []byte) error { _, err := decodeRequest(b); return err }
	rep := func(b []byte) error { _, err := decodeReply(b); return err }
	for _, tc := range []struct {
		name   string
		decode decoder
		line   string
		err    string // "" for none
	}{
		{"keeper hello", keeperHello, `{"keeper":1,"pid":42}`, ""},
		{"keeper hello, later fields", keeperHello, `{"keeper":1,"pid":42,"later":{"x":[1]}}`, ""},
		{"keeper hello, refusal", keeperHello, `{"error":{"kind":"policy","message":"no"}}`, ""},
		{"keeper hello, refusal without a message", keeperHello, `{"error":{"kind":"policy"}}`, "without a kind or a message"},
		{"keeper hello, another version", keeperHello, `{"keeper":2,"pid":42}`, "the keeper speaks version 2; this vegtam speaks 1"},
		{"keeper hello, no pid", keeperHello, `{"keeper":1}`, "did not say its pid"},
		{"keeper hello, null", keeperHello, `null`, "names no version"},
		{"keeper hello, a string", keeperHello, `{"keeper":"1","pid":42}`, "not the protocol's"},
		{"keeper hello, data after", keeperHello, `{"keeper":1,"pid":42} {}`, "not the protocol's"},
		{"run hello", runHello, `{"keeper":1}`, ""},
		{"run hello, another version", runHello, `{"keeper":3}`, "the keeper speaks version 1; this vegtam speaks 3"},
		{"run hello, none", runHello, `{}`, "names no version"},
		{"request", req, `{"id":1,"send":{"ref":"a.http#1","later":1}}`, ""},
		{"request, no id", req, `{"send":{}}`, "without an id"},
		{"request, negative id", req, `{"id":-1,"send":{}}`, "without an id"},
		{"request, null send", req, `{"id":1,"send":null}`, "nothing to send"},
		{"request, an array", req, `[1]`, "not the protocol's"},
		{"reply", rep, `{"id":1,"inbound":{"result":{"ref":"x"}}}`, ""},
		{"reply, error", rep, `{"id":1,"error":{"kind":"network","message":"refused"}}`, ""},
		{"reply, last line", rep, `{"error":{"kind":"policy","message":"bye"}}`, ""},
		{"reply, no id", rep, `{"inbound":{"result":{}}}`, "without an id"},
		{"reply, nothing", rep, `{"id":1}`, "gives back nothing"},
		{"reply, no result", rep, `{"id":1,"inbound":{"captured":[]}}`, "no result"},
		{"reply, both", rep, `{"id":1,"inbound":{"result":{}},"error":{"kind":"policy","message":"no"}}`, "both"},
		{"reply, error without a kind", rep, `{"id":1,"error":{"message":"no"}}`, "without a kind"},
		{"reply, negative id", rep, `{"id":-2,"error":{"kind":"policy","message":"no"}}`, "no run sends"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.decode([]byte(tc.line))
			switch {
			case tc.err == "" && err != nil:
				t.Errorf("error %v", err)
			case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
				t.Errorf("error %v, want %q", err, tc.err)
			}
		})
	}
}

func TestErrorOf(t *testing.T) {
	e := errorOf(core.Errorf(core.KindTimeout, core.Source{File: "a.http", Line: 3}, "no response"))
	if e.Kind != core.KindTimeout || e.Message != "a.http:3: no response" {
		t.Errorf("%+v", e)
	}
	if e := errorOf(io.ErrUnexpectedEOF); e.Kind != core.KindPolicy || e.Message != "unexpected EOF" {
		t.Errorf("%+v", e)
	}
}
