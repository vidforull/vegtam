package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
)

func newTrustCmd(cfg *Config) *cobra.Command {
	var revoke, list bool
	cmd := &cobra.Command{
		Use:   "trust <dir> | --revoke <dir> | --list",
		Short: "Allow the commands of a command file to run",
		Long: `Allow {{$cmd NAME}} placeholders to run the commands of
http-client.cmd.json in a directory, or of the file named. vegtam records
where the file is and a SHA-256 of it and of the files its commands name
by relative paths, such as ./bin/token, in
$XDG_CONFIG_HOME/vegtam/trust.json, ~/.config/vegtam/trust.json if
XDG_CONFIG_HOME is not set. When any of them changes, the commands stop
running until the file is trusted again. The trust holds for the .http
files in the directory and below it.

Read the file and the scripts it names first: they run as you, with your
environment. Trusting is for a person to decide; a program that meets a
"policy" error should ask one rather than run vegtam trust itself.

--revoke takes the trust back. --list shows every file trusted and
whether it is unchanged, changed or gone.`,
		Args: func(cmd *cobra.Command, args []string) error {
			switch {
			case list && revoke:
				return errors.New("--list and --revoke do not go together")
			case list:
				return cobra.NoArgs(cmd, args)
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: func(_ *cobra.Command, args []string) error {
			store := policy.DefaultStore()
			switch {
			case list:
				return listTrusted(cfg, store)
			case revoke:
				return revokeTrust(cfg, store, args[0])
			}
			return trust(cfg, store, args[0])
		},
	}
	cmd.Flags().BoolVar(&revoke, "revoke", false, "take the trust back")
	cmd.Flags().BoolVar(&list, "list", false, "list the trusted files")
	return cmd
}

// commandFile returns the path of the command file arg names: the
// http-client.cmd.json of a directory, or the file itself. A path that
// does not exist, as for revoking the trust in a directory since deleted,
// is taken for a directory unless it ends in the file's name.
func commandFile(arg string) (string, error) {
	fi, err := os.Stat(arg)
	switch {
	case err == nil && fi.IsDir(), err != nil && filepath.Base(arg) != env.CommandFileName:
		return filepath.Join(arg, env.CommandFileName), nil
	case filepath.Base(arg) != env.CommandFileName:
		return "", core.Errorf(core.KindUsage, core.Source{}, "%s is not a command file: vegtam runs commands only from files named %s",
			arg, env.CommandFileName)
	}
	return arg, nil
}

func trust(cfg *Config, store *policy.Store, arg string) error {
	path, err := commandFile(arg)
	if err != nil {
		return err
	}
	if _, err = os.Stat(path); err != nil {
		return core.Errorf(core.KindUsage, core.Source{}, "%v", err)
	}
	// What is trusted is what was read and parsed, byte for byte, with the
	// files its commands name.
	f, err := env.ReadCommandFile(path)
	if err != nil {
		return err
	}
	sum, err := f.Sum()
	if err != nil {
		return core.Errorf(core.KindUsage, core.Source{File: f.Path}, "%v", err)
	}
	if err := store.Trust(f.Path, sum); err != nil {
		return err
	}
	t := &output.Trusted{File: f.Path, Status: string(policy.Trusted), SHA256: sum}
	if cfg.asJSON() {
		cfg.writeJSON(output.Document{SchemaVersion: output.SchemaVersion, Trust: []*output.Trusted{t}})
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Trusted %s. {{$cmd NAME}} now runs:\n", f.Path)
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	for _, name := range slices.Sorted(maps.Keys(f.Commands)) {
		var argv []string
		for _, a := range f.Commands[name].Argv {
			argv = append(argv, core.ShellQuote(a))
		}
		fmt.Fprintf(tw, "  %s\t%s\n", name, strings.Join(argv, " "))
	}
	tw.Flush()
	fmt.Fprint(cfg.out, printable(b.String()))
	return nil
}

func revokeTrust(cfg *Config, store *policy.Store, arg string) error {
	path, err := commandFile(arg)
	if err == nil {
		path, err = policy.Canonical(path)
	}
	if err != nil {
		return core.Errorf(core.KindUsage, core.Source{}, "%v", err)
	}
	was, err := store.Revoke(path)
	if err != nil {
		return err
	}
	switch {
	case cfg.asJSON():
		t := &output.Trusted{File: path, Status: string(policy.Untrusted)}
		if was {
			t.Status = string(policy.Revoked)
		}
		cfg.writeJSON(output.Document{SchemaVersion: output.SchemaVersion, Trust: []*output.Trusted{t}})
	case was:
		fmt.Fprintf(cfg.out, "Revoked the trust in %s: its commands no longer run.\n", printable(path))
	default:
		fmt.Fprintf(cfg.out, "%s was not trusted.\n", printable(path))
	}
	return nil
}

func listTrusted(cfg *Config, store *policy.Store) error {
	m, err := store.List()
	if err != nil {
		return err
	}
	doc := output.Document{SchemaVersion: output.SchemaVersion, Trust: []*output.Trusted{}}
	for _, path := range slices.Sorted(maps.Keys(m)) {
		t := &output.Trusted{File: path, Status: string(policy.Trusted), SHA256: m[path]}
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			t.Status = string(policy.Missing)
		} else if f, err := env.ReadCommandFile(path); err != nil {
			t.Status = string(policy.Changed)
		} else if sum, err := f.Sum(); err != nil || sum != m[path] {
			t.Status = string(policy.Changed)
		}
		doc.Trust = append(doc.Trust, t)
	}
	if cfg.asJSON() {
		cfg.writeJSON(doc)
		return nil
	}
	if len(doc.Trust) == 0 {
		fmt.Fprintln(cfg.out, "No command file is trusted.")
		return nil
	}
	var b bytes.Buffer
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tFILE")
	for _, t := range doc.Trust {
		fmt.Fprintf(tw, "%s\t%s\n", t.Status, t.File)
	}
	tw.Flush()
	fmt.Fprint(cfg.out, printable(b.String()))
	return nil
}
