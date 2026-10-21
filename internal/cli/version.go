package cli

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// versionInfo is the document of vegtam version. Commit and date were
// added after the others; a build that does not record them leaves them
// out.
type versionInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

func newVersionCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long: `Print the vegtam version, the commit it was built from and the date of
that commit, the Go version it was built with, and the target OS and
architecture. What the build did not record is left out. "+dirty" after
the commit means the files built had changes that were not committed.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			info := versionInfo{
				Name:    "vegtam",
				Version: cfg.Version,
				Commit:  cfg.Commit,
				Date:    cfg.Date,
				Go:      runtime.Version(),
				OS:      runtime.GOOS,
				Arch:    runtime.GOARCH,
			}
			if cfg.asJSON() {
				cfg.writeJSON(info)
				return nil
			}
			fmt.Fprint(cfg.out, cfg.text(info.String()+"\n"))
			return nil
		},
	}
}

// String returns the information on one line, such as
//
//	vegtam 0.1.0 (commit 1a2b3c4d5e6f, 2026-10-20T12:00:00Z, go1.27.3, linux/arm64)
//
// with the commit cut to 12 characters.
func (v versionInfo) String() string {
	var about []string
	if v.Commit != "" {
		about = append(about, "commit "+shortCommit(v.Commit))
	}
	if v.Date != "" {
		about = append(about, v.Date)
	}
	about = append(about, v.Go, v.OS+"/"+v.Arch)
	return fmt.Sprintf("%s %s (%s)", v.Name, v.Version, strings.Join(about, ", "))
}

// shortCommit cuts a commit to the 12 characters that Go's
// pseudo-versions keep of it, and keeps what follows a "+", such as
// "+dirty".
func shortCommit(c string) string {
	i := strings.IndexByte(c, '+')
	if i < 0 {
		i = len(c)
	}
	if i <= 12 {
		return c
	}
	return c[:12] + c[i:]
}
