package httpfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/vidforull/vegtam/internal/core"
)

// FuzzParse checks what the parser promises for any input: no panic; an
// error of kind parse at a line of the file; requests with a method and
// a URL, found by name and by position; the same result every time.
func FuzzParse(f *testing.F) {
	paths, err := filepath.Glob("../../../testdata/*/*.http")
	if err != nil || len(paths) == 0 {
		f.Fatalf("no .http files in testdata: %v", err)
	}
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(src)
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		CaptureNames(src)
		file, err := Parse("a.http", src)
		lines := bytes.Count(src, []byte("\n")) + 1
		if err != nil {
			e, ok := errors.AsType[*core.Error](err)
			if !ok || e.Kind != core.KindParse || e.Source.File != "a.http" || e.Source.Line < 1 || e.Source.Line > lines {
				t.Fatalf("error %#v", err)
			}
			return
		}
		names := map[string]bool{}
		for i, r := range file.Requests {
			if !IsMethod(r.Method) || r.URL == "" || r.Source.File != "a.http" || r.Source.Line < 1 || r.Source.Line > lines {
				t.Fatalf("request %d: %+v", i+1, r)
			}
			if got, ok := file.Find(strconv.Itoa(i + 1)); !ok || got != r {
				t.Fatalf("Find(%d) = %+v, want %+v", i+1, got, r)
			}
			if r.Name == "" {
				continue
			}
			if names[r.Name] || isNumber(r.Name) {
				t.Fatalf("request name %q twice or a number", r.Name)
			}
			names[r.Name] = true
			if got, ok := file.Find(r.Name); !ok || got != r {
				t.Fatalf("Find(%q) = %+v, want %+v", r.Name, got, r)
			}
		}
		if again, err := Parse("a.http", src); err != nil || !reflect.DeepEqual(again, file) {
			t.Fatalf("parsed again: %+v, %v", again, err)
		}
	})
}
