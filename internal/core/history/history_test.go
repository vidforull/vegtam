package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// entry returns the i-th entry of a test.
func entry(i int) Entry {
	return Entry{
		Time: time.Date(2026, 10, 19, 12, 0, i, 0, time.FixedZone("CEST", 2*3600)), Ref: "/api/x.http#" + strconv.Itoa(i),
		Env: "dev", Method: "GET", URL: "{{host}}/items/" + strconv.Itoa(i), Status: 200, DurationMS: 1.5, Result: "ok",
	}
}

// refs returns the refs of entries, in order.
func refs(entries []Entry) string {
	var s []string
	for _, e := range entries {
		s = append(s, strings.TrimPrefix(e.Ref, "/api/x.http#"))
	}
	return strings.Join(s, " ")
}

// newLog returns a history in a directory of its own, which only its
// owner can write, as Add makes it: t.TempDir may be group-writable.
func newLog(t *testing.T) *Log {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vegtam")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return New(dir)
}

func add(t *testing.T, l *Log, entries ...Entry) {
	t.Helper()
	for _, e := range entries {
		if err := l.Add(e); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdd(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data", "vegtam")
	l := New(dir)
	add(t, l, entry(1), entry(2))
	b, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"time":"2026-10-19T10:00:01Z","ref":"/api/x.http#1","env":"dev","method":"GET","url":"{{host}}/items/1",` +
		`"status":200,"duration_ms":1.5,"result":"ok"}` + "\n"
	if lines := strings.SplitAfter(string(b), "\n"); len(lines) != 3 || lines[0] != want {
		t.Errorf("history file:\n%s\nwant first line\n%s", b, want)
	}
	for path, mode := range map[string]os.FileMode{dir: 0o700, l.Path(): 0o600} {
		if fi, serr := os.Stat(path); serr != nil || fi.Mode().Perm() != mode {
			t.Errorf("%s: %v, %v; want mode %v", path, fi.Mode(), serr, mode)
		}
	}

	// A file that something else made readable to others is made private.
	if err = os.Chmod(l.Path(), 0o644); err != nil {
		t.Fatal(err)
	}
	add(t, l, entry(3))
	if fi, serr := os.Stat(l.Path()); serr != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("after an add to a 0644 file: %v, %v", fi.Mode(), serr)
	}

	// Each text is cut after 2 KiB, on a character: a long name must not
	// make the file start anew on every run.
	long := entry(4)
	long.URL, long.Ref = strings.Repeat("é", maxField), "/api/x.http#"+strings.Repeat("n", 1<<20)
	add(t, l, long)
	got, err := l.Last(1)
	if err != nil || len(got) != 1 || len(got[0].URL) != maxField+len("...") || !strings.HasSuffix(got[0].URL, "é...") ||
		len(got[0].Ref) != maxField+len("...") {
		t.Errorf("long texts: URL %d bytes, ref %d, %v", len(got[0].URL), len(got[0].Ref), err)
	}

	// A password written in a URL is not kept; a placeholder in its place
	// is not either.
	for url, want := range map[string]string{
		"https://ada:Hunter2@{{host}}/x?a=b@c":   "https://ada:***@{{host}}/x?a=b@c",
		"http://ada:{{pass}}@example.test":       "http://ada:***@example.test",
		"https://example.test:8443/x?mail=a@b.c": "https://example.test:8443/x?mail=a@b.c",
		"{{host}}/x":                             "{{host}}/x",
	} {
		e := entry(5)
		e.URL = url
		add(t, l, e)
		if got, err = l.Last(1); err != nil || got[0].URL != want {
			t.Errorf("URL %q kept as %q, want %q", url, got[0].URL, want)
		}
	}
}

// TestDirWritableByOthers checks that the history is not added to in a
// directory that others can write: they could swap the file.
func TestDirWritableByOthers(t *testing.T) {
	l := newLog(t)
	add(t, l, entry(1))
	if err := os.Chmod(filepath.Dir(l.Path()), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := l.Add(entry(2)); err == nil || !strings.Contains(err.Error(), "others can write") {
		t.Errorf("Add = %v", err)
	}
	if got, err := l.Last(5); err != nil || len(got) != 1 {
		t.Errorf("Last = %d entries, %v", len(got), err)
	}
}

func TestLast(t *testing.T) {
	l := newLog(t)
	if got, err := l.Last(10); err != nil || len(got) != 0 {
		t.Fatalf("without a file: %v, %v", got, err)
	}
	if got, err := New(filepath.Join(t.TempDir(), "none")).Last(10); err != nil || len(got) != 0 {
		t.Fatalf("without a directory: %v, %v", got, err)
	}
	for i := 1; i <= 5; i++ {
		add(t, l, entry(i))
	}
	got, err := l.Last(3)
	if err != nil || refs(got) != "5 4 3" {
		t.Errorf("Last(3) = %q, %v", refs(got), err)
	}
	if !got[0].Time.Equal(entry(5).Time) || got[0].Time.Location() != time.UTC {
		t.Errorf("time = %v", got[0].Time)
	}
	if got, err = l.Last(10); err != nil || refs(got) != "5 4 3 2 1" {
		t.Errorf("Last(10) = %q, %v", refs(got), err)
	}

	// Lines that are no entries are skipped: broken JSON, JSON of another
	// shape, and a line a killed run left without its line feed.
	f, err := os.OpenFile(l.Path(), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteString("{\"time\": \"2026\n[1, 2]\n\n{}\n"); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	add(t, l, entry(6))
	b, _ := os.ReadFile(l.Path())
	if err = os.WriteFile(l.Path(), append(b, `{"time":"2026-10-19T10:00:07Z","ref":"/api/x.http#7"`...), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err = l.Last(3); err != nil || refs(got) != "6 5 4" {
		t.Errorf("with broken lines: Last(3) = %q, %v", refs(got), err)
	}
}

// TestLastReadsTheEnd checks that Last reads no more of a file than it
// must: the end of a file larger than any vegtam writes still gives its
// last entries.
func TestLastReadsTheEnd(t *testing.T) {
	l := newLog(t)
	junk := strings.Repeat("x", 3*MaxSize) // no line feed: reading it whole would find none
	if err := os.WriteFile(l.Path(), []byte(junk+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	add(t, l, entry(1), entry(2))
	if got, err := l.Last(5); err != nil || refs(got) != "2 1" {
		t.Errorf("Last(5) = %q, %v", refs(got), err)
	}
}

func TestRotate(t *testing.T) {
	l := newLog(t)
	e := entry(1)
	e.Time = e.Time.UTC()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	line := len(b) + 1
	per := MaxSize / line // the entries that fit one file
	n := 0
	next := func(count int) {
		for range count {
			n++
			e.Status = 200 + n%100 // the same length every time
			add(t, l, e)
		}
	}
	next(per)
	if _, err = os.Stat(l.Path() + ".1"); err == nil {
		t.Fatalf("rotated after %d entries, which fit", per)
	}
	next(1)
	fi, err := os.Stat(l.Path() + ".1")
	if err != nil || fi.Size() > MaxSize {
		t.Fatalf("after %d entries: %v, %v", per+1, fi, err)
	}
	if cur, err := os.Stat(l.Path()); err != nil || cur.Size() != int64(line) {
		t.Errorf("the new file: %v, %v", cur, err)
	}
	// Last reads on into the file before.
	if got, err := l.Last(3); err != nil || len(got) != 3 || got[0].Status != 200+n%100 || got[2].Status != 200+(n-2)%100 {
		t.Errorf("Last(3) after rotating: %+v, %v", got, err)
	}
	// One file before, no more.
	next(per)
	if matches, _ := filepath.Glob(l.Path() + "*"); len(matches) != 2 {
		t.Errorf("files: %q", matches)
	}
}

// TestStaysInside checks that a history file that is a symbolic link
// leading out of its directory is neither written nor read.
func TestStaysInside(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(outside, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := newLog(t)
	if err := os.Symlink(outside, l.Path()); err != nil {
		t.Fatal(err)
	}
	if err := l.Add(entry(1)); err == nil {
		t.Error("Add through a symbolic link out of the directory: no error")
	}
	if _, err := l.Last(1); err == nil {
		t.Error("Last through a symbolic link out of the directory: no error")
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep\n" {
		t.Errorf("the file outside holds %q", b)
	}
}

// TestConcurrentAdds checks that lines added at once stay whole.
func TestConcurrentAdds(t *testing.T) {
	l := newLog(t)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		wg.Go(func() { errs <- l.Add(entry(i)) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got, err := l.Last(100); err != nil || len(got) != 20 {
		t.Errorf("%d entries, %v", len(got), err)
	}
}
