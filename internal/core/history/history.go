// Package history keeps the history of runs: one line of JSON for each
// request sent, with where it is written, how it was sent and how it
// ended, and nothing that a secret could be in. A request's URL is kept
// as written in its file, with its placeholders, never as resolved; its
// headers, its body, the response, the values of variables and what
// captures took are not kept in any form.
//
// The file is history.jsonl in vegtam's data directory, readable by its
// owner only. A run adds a line to its end; once the file would grow past
// MaxSize, it becomes history.jsonl.1, replacing the one before, and a new
// file starts.
package history

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"
)

const (
	// FileName is the name of the history file in its directory; the one
	// before it has ".1" added.
	FileName = "history.jsonl"
	// MaxSize is how large the file grows before it starts anew.
	MaxSize = 1 << 20
	// maxField is how many bytes of each text an entry keeps: a request
	// name or a URL of any length must not crowd the others out.
	maxField = 2048
	// maxRead is how many bytes from the end of a file Last reads at
	// most: a file vegtam wrote is never larger, and one it did not write
	// must not make the interface read without end.
	maxRead = 2 * MaxSize
)

// Entry is one run of a request. Fields are only ever added. Add cuts
// each text after 2 KiB, with "..." after it.
type Entry struct {
	Time       time.Time `json:"time"`               // when it started, UTC
	Ref        string    `json:"ref"`                // file#name or file#N, the file an absolute path
	Env        string    `json:"env,omitempty"`      // the environment; none if empty
	Method     string    `json:"method"`             // as written
	URL        string    `json:"url"`                // as written, placeholders included, a password in it as ***
	Status     int       `json:"status,omitempty"`   // of the response; absent without one
	DurationMS float64   `json:"duration_ms"`        // until the end of the response, or of the run without one
	Result     string    `json:"result"`             // "ok", or the kind of the error, such as "assert" or "network"
	Truncated  bool      `json:"truncated,omitzero"` // the response body was longer than --max-body
	// Redacted is set when what a run without a person was shown of the
	// response was made sterile (see output.Result.Redact).
	Redacted bool `json:"redacted,omitzero"`
}

// Log is the history file in a directory. A Log holds no state of its
// own, so several goroutines may use it, and several processes may add
// to the same file.
type Log struct {
	dir string
}

// New returns the history kept in dir/history.jsonl.
func New(dir string) *Log { return &Log{dir: dir} }

// Path returns the history file.
func (l *Log) Path() string { return filepath.Join(l.dir, FileName) }

// Add appends e to the history, creating the directory (0700) and the
// file (0600) if need be, and refusing a directory that others can
// write. The line is written with one write and synced before Add
// returns.
func (l *Log) Add(e Entry) error {
	e.Time = e.Time.UTC()
	e.URL = password.ReplaceAllString(e.URL, "$1:***@")
	for _, s := range []*string{&e.Ref, &e.Env, &e.Method, &e.URL, &e.Result} {
		*s = cut(*s)
	}
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return err
	}
	var line bytes.Buffer
	enc := json.NewEncoder(&line) // which ends the line
	enc.SetEscapeHTML(false)      // & in a query stays &
	if err := enc.Encode(e); err != nil {
		return err
	}
	// Through an os.Root of the directory: a history file that is a
	// symbolic link to elsewhere is not written to.
	root, err := os.OpenRoot(l.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	// Whoever else can write the directory can swap the file for another.
	if fi, err := root.Stat("."); err != nil {
		return err
	} else if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("others can write %s; make it private: chmod 700 %s", l.dir, l.dir)
	}
	if err := rotate(root, line.Len()); err != nil {
		return err
	}
	return appendLine(root, line.Bytes())
}

// password matches the password of the user information of a URL, as
// written: "https://ada:" and what follows up to the "@".
var password = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*://[^/?#@:]*):[^/?#@]*@`)

// cut returns s cut after maxField bytes, on a character, with "..."
// after it.
func cut(s string) string {
	if len(s) <= maxField {
		return s
	}
	i := maxField
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i] + "..."
}

// appendLine adds line to the end of the history file in root.
func appendLine(root *os.Root, line []byte) (err error) {
	f, err := root.OpenFile(FileName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) //nolint:forbidigo // appends one line: Sync and Close are checked
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	// A file made by something else keeps no looser mode.
	fi, err := f.Stat()
	if err == nil && fi.Mode().Perm()&0o077 != 0 {
		err = f.Chmod(0o600)
	}
	if err == nil {
		_, err = f.Write(line)
	}
	if err == nil {
		err = f.Sync()
	}
	return err
}

// rotate makes the history file the one before, if adding n bytes would
// grow it past MaxSize.
func rotate(root *os.Root, n int) error {
	fi, err := root.Stat(FileName)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !fi.Mode().IsRegular(): // opening a FIFO would wait for a reader
		return fmt.Errorf("%s is not a regular file", filepath.Join(root.Name(), FileName))
	case fi.Size()+int64(n) <= MaxSize:
		return nil
	}
	// Another run may have just started a new file; then the one before
	// is lost, which a history can bear.
	if err = root.Rename(FileName, FileName+".1"); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Last returns the latest n entries, the latest first, from the history
// file and, if it has fewer, from the one before it. It reads only the
// end of each file. A line that is not an entry, such as one cut short
// when a run was killed, is skipped. Without a history file, there are
// none.
func (l *Log) Last(n int) ([]Entry, error) {
	if n <= 0 {
		return nil, nil
	}
	root, err := os.OpenRoot(l.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer root.Close()
	var entries []Entry
	for _, name := range []string{FileName, FileName + ".1"} {
		got, err := last(root, name, n-len(entries))
		if err != nil {
			return nil, err
		}
		if entries = append(entries, got...); len(entries) == n {
			break
		}
	}
	return entries, nil
}

// last returns the latest n entries of the file name in root, the latest
// first. It reads lines from the end until n of them are entries.
func last(root *os.Root, name string, n int) ([]Entry, error) {
	for want := n; ; want *= 2 {
		lines, err := tail(root, name, want)
		if err != nil {
			return nil, err
		}
		var entries []Entry
		for _, line := range slices.Backward(lines) {
			var e Entry
			if json.Unmarshal(line, &e) == nil && e.Ref != "" && !e.Time.IsZero() {
				if entries = append(entries, e); len(entries) == n {
					return entries, nil
				}
			}
		}
		if len(lines) < want { // no more lines to read
			return entries, nil
		}
	}
}

// tail returns the last n whole lines of the file name in root, without
// their line feeds, the last one last. A line that does not end with a
// line feed is not whole: a run is adding it, or was killed doing so.
func tail(root *os.Root, name string, n int) (lines [][]byte, err error) {
	fi, err := root.Stat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	case !fi.Mode().IsRegular(): // opening a FIFO would wait for a writer
		return nil, fmt.Errorf("%s is not a regular file", filepath.Join(root.Name(), name))
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	if fi, err = f.Stat(); err != nil {
		return nil, err
	}
	const chunk = 64 << 10
	end, start := fi.Size(), fi.Size()
	var buf []byte
	// Back from the end, a chunk at a time, until n line feeds precede
	// the last one: then the first of the n lines is whole too.
	for start > 0 && end-start < maxRead && bytes.Count(buf, []byte("\n")) <= n {
		next := max(start-chunk, 0)
		b := make([]byte, start-next, start-next+int64(len(buf)))
		if _, err = f.ReadAt(b, next); err != nil {
			return nil, err
		}
		buf, start = append(b, buf...), next
	}
	all := bytes.Split(buf, []byte("\n"))
	all = all[:len(all)-1] // after the last line feed
	if start > 0 && len(all) > 0 {
		all = all[1:] // before the first line feed read: part of a line
	}
	return all[max(len(all)-n, 0):], nil
}
