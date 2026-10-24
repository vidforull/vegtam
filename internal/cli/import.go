package cli

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/importer/postman"
)

func newImportCmd(cfg *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Convert requests from other tools into .http files",
		// Runnable, so that cobra checks the arguments: an unknown tool
		// is an error, not a request for help.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newImportPostmanCmd(cfg))
	return cmd
}

func newImportPostmanCmd(cfg *Config) *cobra.Command {
	var out string
	var force bool
	cmd := &cobra.Command{
		Use:   "postman <export-dir>|<collection.json> -o <dir>",
		Short: "Convert a Postman export into .http files",
		Long: `Convert a Postman export into .http and environment files under -o: a
collection file (Collection v2.1 or v2.0), or the directory of an export
with collections, environments and globals.

Each collection becomes a directory, each folder a .http file. Variables
go to http-client.env.json, one environment per Postman environment.
Secrets go to http-client.private.env.json, and so do literal values
from auth and from headers, query parameters and form or JSON fields
named like secrets; its $allow binds each secret to the one origin its
requests go to, where the export makes that plain. Scripts are not
imported. The report lists what was not imported and why, the secrets
to bind, and the variables to check or set.

Existing files are not overwritten without --force; then nothing is
written.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			res, err := postman.Import(args[0], out)
			if err != nil {
				return err
			}
			if err := writeFiles(out, res.Files, force); err != nil {
				return err
			}
			if cfg.asJSON() {
				cfg.writeJSON(output.Document{SchemaVersion: output.SchemaVersion, Import: res.Report})
				return nil
			}
			fmt.Fprint(cfg.out, cfg.text(importText(res.Report)))
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "the directory to write to")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files")
	if err := cmd.MarkFlagRequired("output"); err != nil {
		panic(err) // only if the flag above were renamed
	}
	return cmd
}

// writeFiles writes files under dir, through an os.Root so that no path
// leads outside it. Without force, nothing is written if any file exists.
// The directories it makes are private: each collection holds secrets.
func writeFiles(dir string, files []postman.File, force bool) error {
	fail := func(err error) error { return core.Errorf(core.KindUsage, core.Source{}, "%v", err) }
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fail(err)
	}
	defer root.Close()
	var exist []string
	for _, f := range files {
		fi, err := root.Lstat(filepath.FromSlash(f.Path))
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return fail(err)
		case !fi.Mode().IsRegular():
			return core.Errorf(core.KindUsage, core.Source{}, "%s exists and is not a regular file", filepath.Join(dir, f.Path))
		default:
			exist = append(exist, filepath.Join(dir, f.Path))
		}
	}
	if len(exist) > 0 && !force {
		return core.Errorf(core.KindUsage, core.Source{}, "%d files exist (use --force to overwrite them): %s",
			len(exist), strings.Join(exist, ", "))
	}
	for _, f := range files {
		p := filepath.FromSlash(f.Path)
		perm := fs.FileMode(0o644)
		if f.Private {
			perm = 0o600
		}
		if err := root.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return fail(err)
		}
		if err := writeFile(root, p, f.Data, perm); err != nil {
			return fail(err)
		}
	}
	return nil
}

// writeFile writes data to the file name under root: to a new file beside
// it, synced and closed, then renamed over name. name never holds part of
// the data, and the mode of an old file, such as 0644 on one that now
// holds secrets, does not carry over: the file has mode perm.
func writeFile(root *os.Root, name string, data []byte, perm fs.FileMode) error {
	tmp := filepath.Join(filepath.Dir(name), "."+filepath.Base(name)+"."+rand.Text()+".tmp")
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) //nolint:forbidigo // the one write of import: Sync, Close and Rename are checked
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmp, name)
	}
	if err != nil {
		root.Remove(tmp)
	}
	return err
}

// categories are the kinds of skipped things, in the order the text
// report gives them, with what each heading says.
var categories = []struct{ name, title string }{
	{"request", "requests written commented out"},
	{"body", "bodies and form fields not imported"},
	{"auth", "auth settings not imported"},
	{"script", "scripts not imported"},
	{"variable", "variables renamed, not supported or not bound"},
	{"header", "disabled headers, written as comments"},
	{"example", "saved responses not imported"},
	{"setting", "request settings not imported"},
	{"file", "files of the export not read"},
}

// importText is the report of an import, for a terminal.
func importText(r *output.Import) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Imported %d of %d requests from %d collections into %s, with %d environments: %s.\n",
		r.Imported, r.Requests, r.Collections, r.Output, len(r.Environments), strings.Join(r.Environments, ", "))
	byCategory := map[string][]output.Skipped{}
	for _, s := range r.Skipped {
		byCategory[s.Category] = append(byCategory[s.Category], s)
	}
	for _, c := range categories {
		if len(byCategory[c.name]) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s: %d %s\n", c.name, len(byCategory[c.name]), c.title)
		for _, s := range byCategory[c.name] {
			fmt.Fprintf(&b, "  %s: %s\n", s.Where, s.Reason)
		}
	}
	if len(r.Variables) > 0 {
		b.WriteString("\nVariables to check or set:\n")
		for _, v := range r.Variables {
			what := "check its value in"
			if v.Status == "unset" {
				what = "it has no value; set it in"
			}
			more := ""
			if len(v.Files) > 1 {
				more = fmt.Sprintf(" and %d more", len(v.Files)-1)
			}
			fmt.Fprintf(&b, "  %s (%s): %s %s%s\n", v.Name, v.Status, what, v.Files[0], more)
		}
	}
	fmt.Fprintf(&b, "\nKeep the %s files out of version control: they hold the secrets.\n", env.PrivateFile)
	fmt.Fprintf(&b, "\nCheck the requests without sending them: vegtam run %s --dry-run -e %s\n",
		shellQuote(r.Output), shellQuote(r.Environments[0]))
	return b.String()
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_./:@%+=-]+$`)

// shellQuote quotes s for a POSIX shell if it needs quoting.
func shellQuote(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
