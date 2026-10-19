package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestFormatJSON(t *testing.T) {
	doc := `{"id": 7, "user": {"name": "Ada", "tags": ["a", "b"]}, "empty": {}, "none": [],` +
		` "list": [{"x": 1}], "text": "{not [a block]}", "esc": "q\"{"}`
	for _, tt := range []struct {
		fold int
		want string
	}{
		{0, `{
  "id": 7,
  "user": {
    "name": "Ada",
    "tags": [
      "a",
      "b"
    ]
  },
  "empty": {},
  "none": [],
  "list": [
    {
      "x": 1
    }
  ],
  "text": "{not [a block]}",
  "esc": "q\"{"
}`},
		{1, `{
  "id": 7,
  "user": {… 2 keys},
  "empty": {},
  "none": [],
  "list": [… 1 item],
  "text": "{not [a block]}",
  "esc": "q\"{"
}`},
		{2, `{
  "id": 7,
  "user": {
    "name": "Ada",
    "tags": [… 2 items]
  },
  "empty": {},
  "none": [],
  "list": [
    {… 1 key}
  ],
  "text": "{not [a block]}",
  "esc": "q\"{"
}`},
	} {
		got, ok := FormatJSON(doc, tt.fold)
		if !ok || got != tt.want {
			t.Errorf("FormatJSON(fold %d) = %v\n%s\nwant\n%s", tt.fold, ok, got, tt.want)
		}
	}
	if got, ok := FormatJSON(`[1, [2], {"a": [3, 4]}]`, 1); !ok || got != "[\n  1,\n  [… 1 item],\n  {… 1 key}\n]" {
		t.Errorf("an array at fold 1: %q", got)
	}
	for _, s := range []string{`{"a": 1}`, `[]`} {
		if got, _ := FormatJSON(s, 0); got == "" || strings.Contains(got, "…") {
			t.Errorf("FormatJSON(%q, 0) = %q", s, got)
		}
	}
	if got, _ := FormatJSON(`{"a": 1}`, 1); got != "{\n  \"a\": 1\n}" {
		t.Errorf("the value itself is never folded: %q", got)
	}
	for _, s := range []string{"", "text", `{"a": 1`, `{"a": 1} {}`, "{\"a\": \"\x01\"}"} {
		if got, ok := FormatJSON(s, 1); ok || got != s {
			t.Errorf("FormatJSON(%q) = %q, %v; want it unchanged", s, got, ok)
		}
	}
}

// TestWriteResponseFold checks that the CLI's text form, which does not
// fold, indents JSON as json.Indent does, and that a fold reaches the body.
func TestWriteResponseFold(t *testing.T) {
	res := &Result{Response: &Response{Proto: "HTTP/1.1", Status: 200, Reason: "OK", Body: `{"a":{"b":1}}`}}
	var b strings.Builder
	WriteResponse(&b, res, false, 0)
	var want bytes.Buffer
	if err := json.Indent(&want, []byte(res.Response.Body), "", "  "); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(b.String(), "\n\n"+want.String()+"\n") {
		t.Errorf("WriteResponse, no fold:\n%s", b.String())
	}
	b.Reset()
	WriteResponse(&b, res, false, 1)
	if !strings.Contains(b.String(), "\n{\n  \"a\": {… 1 key}\n}\n") {
		t.Errorf("WriteResponse, fold 1:\n%s", b.String())
	}
}

// FuzzFormatJSON checks that formatting any text does not panic, leaves
// text that is not JSON as it is, and folds nothing but whole objects and
// arrays: put back, each fold gives the text that folds nothing.
func FuzzFormatJSON(f *testing.F) {
	for _, s := range []string{
		`{"a": {"b": [1, 2, {"c": null}]}, "d": "}{][\"", "e": []}`, `[[[[]]]]`, `"x"`, `{"a":1} x`, `{"k": "{"}`,
		`[{"a": 1}, {"a": 1, "a": 2}]`, " \t{\"a\": [true, false]}\r\n", `{"{… 1 key}": "[… 2 items]"}`,
	} {
		f.Add(s, uint8(1))
	}
	f.Fuzz(func(t *testing.T, s string, fold uint8) {
		n := int(fold % 4)
		got, ok := FormatJSON(s, n)
		full, fullOK := FormatJSON(s, 0)
		switch {
		case ok != fullOK:
			t.Fatalf("FormatJSON(%q): %v with fold %d, %v without", s, ok, n, fullOK)
		case !ok && got != s:
			t.Fatalf("FormatJSON(%q) = %q: not JSON, yet changed", s, got)
		case !ok:
			return
		}
		if err := unfolds(got, full); err != nil {
			t.Fatalf("FormatJSON(%q, %d) = %q\nunfolded = %q\n%v", s, n, got, full, err)
		}
	})
}

var summaryRE = regexp.MustCompile(`^([{\[])… (\d+) (keys?|items?)[}\]]`)

// unfolds checks that folded is full with some of its objects and arrays
// in place of their summaries, and that each summary counts right. It
// reads the blocks with encoding/json, not with the code it checks.
func unfolds(folded, full string) error {
	i, j := 0, 0
	for i < len(folded) {
		if m := summaryRE.FindStringSubmatch(folded[i:]); m != nil && j < len(full) && full[j] == m[1][0] &&
			!strings.HasPrefix(full[j+1:], "…") {
			end, n, err := block(full[j:])
			if err != nil {
				return fmt.Errorf("at %d: %w", j, err)
			}
			if want, _ := strconv.Atoi(m[2]); n != want {
				return fmt.Errorf("at %d: %q, but the block has %d", i, m[0], n)
			}
			i, j = i+len(m[0]), j+end
			continue
		}
		if j >= len(full) || folded[i] != full[j] {
			return fmt.Errorf("differs at %d: %q, unfolded at %d: %q", i, folded[i:], j, full[min(j, len(full)):])
		}
		i, j = i+1, j+1
	}
	if j != len(full) {
		return fmt.Errorf("the rest is missing: %q", full[j:])
	}
	return nil
}

// block returns the length of the object or array at the start of s, and
// how many members or items it has.
func block(s string) (end, n int, err error) {
	dec := json.NewDecoder(strings.NewReader(s))
	tokens, depth := 0, 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return 0, 0, err
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			if depth == 1 {
				tokens++
			}
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		default:
			if depth == 1 {
				tokens++
			}
		}
		if depth == 0 {
			if s[0] == '{' {
				tokens /= 2 // a key and its value
			}
			return int(dec.InputOffset()), tokens, nil
		}
	}
}

func TestPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"plain\ttext\n":                "plain\ttext\n",
		"a\r\nb":                       "a\nb",
		"\x1b]0;title\x07":             `\x1b]0;title\x07`,
		"\u009b2J \x9b2J":              `\x9b2J \x9b2J`,
		"\u202egnp.exe":                `\u202egnp.exe`,
		"\u2066a\u2069 \u200eb\u200f":  `\u2066a\u2069 \u200eb\u200f`,
		"zero\u200bwidth\ufeff":        `zero\u200bwidth\ufeff`,
		"soft\u00adhyphen\u2060":       `soft\u00adhyphen\u2060`,
		"tag \U000e0041\U000e007f":     `tag \U000e0041\U000e007f`,
		"caf\xe9 caf\u00e9 \U0001f600": `caf\xe9 café 😀`,
		`\u202e`:                       `\u202e`, // already shown escaped: as it is
		"a\u2028b\u2029c":              `a\u2028b\u2029c`,
		"\u3164 \u034f":                `\u3164 \u034f`,
		"x\U000e0100\U000e01ef":        `x\U000e0100\U000e01ef`,
		"\u2764\ufe0f \u00e9":          "\u2764\ufe0f \u00e9", // an emoji's selector, a letter: as they are
	} {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %q, want %q", in, got, want)
		}
	}
}
