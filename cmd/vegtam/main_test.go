package main

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func TestStamp(t *testing.T) {
	const (
		rev    = "6c213c9b45cd9fe0d834d0bc8b65db6881b10f4e"
		other  = "fb81cc1d7a1e0b2c3d4e5f60718293a4b5c6d7e8"
		when   = "2026-10-20T10:22:32Z"
		pseudo = "v0.0.0-20261020102232-6c213c9b45cd"
	)
	// info is what the go command records: the main module's version and
	// the settings of git, if any.
	info := func(version string, settings ...string) *debug.BuildInfo {
		bi := &debug.BuildInfo{Main: debug.Module{Path: "github.com/vidforull/vegtam", Version: version}}
		for i := 0; i+1 < len(settings); i += 2 {
			bi.Settings = append(bi.Settings, debug.BuildSetting{Key: settings[i], Value: settings[i+1]})
		}
		return bi
	}
	vcs := func(modified string) []string {
		return []string{"vcs", "git", "vcs.revision", rev, "vcs.time", when, "vcs.modified", modified}
	}
	tests := []struct {
		name                  string
		version, commit, date string // set at build time
		bi                    *debug.BuildInfo
		want                  [3]string
	}{
		{"no build information", "dev", "", "", nil, [3]string{"dev", "", ""}},
		{"empty values set, no build information", "", "", "", nil, [3]string{"dev", "", ""}},
		{"empty values set", "", "", "", info(pseudo, vcs("false")...), [3]string{pseudo, rev, when}},
		{"go run, go build -buildvcs=false", "dev", "", "", info("(devel)"), [3]string{"dev", "", ""}},
		{"go install of a tag", "dev", "", "", info("v0.1.0"), [3]string{"v0.1.0", "", ""}},
		{"go build in a checkout", "dev", "", "", info(pseudo, vcs("false")...), [3]string{pseudo, rev, when}},
		{"go build of changed files", "dev", "", "", info(pseudo+"+dirty", vcs("true")...), [3]string{pseudo + "+dirty", rev + "+dirty", when}},
		{"a release", "0.1.0", rev, when, info(pseudo, vcs("false")...), [3]string{"0.1.0", rev, when}},
		{"a snapshot of changed files", "0.0.0-SNAPSHOT-6c213c9", rev, when, info(pseudo+"+dirty", vcs("true")...), [3]string{"0.0.0-SNAPSHOT-6c213c9", rev + "+dirty", when}},
		{"the version alone set", "0.1.0-1-g6c213c9", "", "", info(pseudo, vcs("false")...), [3]string{"0.1.0-1-g6c213c9", rev, when}},
		{"make build of changed files", "6c213c9-dirty", rev, when, info(pseudo+"+dirty", vcs("true")...), [3]string{"6c213c9-dirty", rev + "+dirty", when}},
		// Another commit set at build time: what bi says of its own is not
		// about that one.
		{"another commit set", "0.1.0", other, "", info(pseudo, vcs("true")...), [3]string{"0.1.0", other, ""}},
		{"a date set", "dev", "", "2026-10-21T00:00:00Z", info(pseudo, vcs("false")...), [3]string{pseudo, rev, "2026-10-21T00:00:00Z"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, c, d := stamp(tt.version, tt.commit, tt.date, tt.bi)
			if got := [3]string{v, c, d}; got != tt.want {
				t.Errorf("stamp(%q, %q, %q) = %q, want %q", tt.version, tt.commit, tt.date, got, tt.want)
			}
		})
	}
}

// TestStampOfThisBinary checks stamp against what the go command
// recorded in the test binary, whatever that is: it must not fail, and
// the version is never empty.
func TestStampOfThisBinary(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("no build information in the test binary")
	}
	if v, _, _ := stamp("dev", "", "", bi); v == "" {
		t.Error("stamp of the test binary has an empty version")
	}
}

func TestIsTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, r, w)
	if isTerminal(w) {
		t.Error("isTerminal(pipe) = true, want false")
	}

	f, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	closeAtEnd(t, f)
	if isTerminal(f) {
		t.Error("isTerminal(regular file) = true, want false")
	}
}

// closeAtEnd closes files when the test ends.
func closeAtEnd(t *testing.T, files ...*os.File) {
	t.Helper()
	t.Cleanup(func() {
		for _, f := range files {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		}
	})
}
