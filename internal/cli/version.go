package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

type versionInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

func newVersionCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long: `Print the vegtam version, the Go version it was built with, and the target
OS and architecture.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			info := versionInfo{
				Name:    "vegtam",
				Version: cfg.Version,
				Go:      runtime.Version(),
				OS:      runtime.GOOS,
				Arch:    runtime.GOARCH,
			}
			if cfg.asJSON() {
				cfg.writeJSON(info)
				return nil
			}
			fmt.Fprintf(cfg.Stdout, "%s %s (%s, %s/%s)\n", info.Name, info.Version, info.Go, info.OS, info.Arch)
			return nil
		},
	}
}
