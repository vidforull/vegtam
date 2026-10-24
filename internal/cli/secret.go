package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/store"
)

// maxSecret is the most bytes of a secret's value that --stdin reads.
const maxSecret = 1 << 20

func newSecretCmd(cfg *Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Keep secrets in an encrypted store of your own",
		Long: `Keep secrets in the store: secrets.enc in vegtam's configuration
directory, $XDG_CONFIG_HOME/vegtam or ~/.config/vegtam, readable by you
alone, encrypted under a password (Argon2id and XChaCha20-Poly1305). For
each secret, by name, it holds its value and the origins it may go to:
none until vegtam secret allow binds it, as $allow binds a value of
http-client.private.env.json.

A request's {{name}} takes a value of the store when the private
environment file beside the requests does not give it: the file first,
then the store. The keeper reads the store alone (see vegtam keeper
--help): a program that runs vegtam without a person never sees its
values. vegtam asks for the password at the terminal, once a run needs a
value from the store; it is never taken from a flag, a variable or a
file. The names and their origins are in the clear in the file, and need
no password: vegtam secret list shows them, and a run without a person
knows them. No command prints a value.`,
	}
	cmd.AddCommand(newSecretListCmd(cfg), newSecretSetCmd(cfg), newSecretRmCmd(cfg), newSecretOriginsCmd(cfg, true),
		newSecretOriginsCmd(cfg, false), newSecretImportCmd(cfg))
	return cmd
}

func newSecretListCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the secrets of the store, and where each may go",
		Long: `List the secrets of the store by name, each with the origins it may go
to. It needs no password, and shows no value.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			doc, err := listStore()
			if err != nil {
				return err
			}
			cfg.printStore(doc, "")
			return nil
		},
	}
}

func newSecretSetCmd(cfg *Config) *cobra.Command {
	var stdin bool
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Put a secret in the store, or change its value",
		Long: `Put the secret name in the store, or change its value; its origins
stay. The value is typed at the terminal, without echo, or read from
stdin with --stdin, less one final line break: never from an argument,
which other processes can read. Without a store, set makes one, and asks
for its new password twice.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			if !core.IsVarName(name) {
				return usage("%q: want the name of a variable, as {{name}} names it", name)
			}
			value, err := cfg.secretValue(name, stdin)
			if err != nil {
				return err
			}
			defer clear(value)
			return cfg.changeStore(true, nil, func(s *store.Store) (string, error) {
				_, had := s.Get(name)
				if err := s.Set(name, string(value)); err != nil {
					return "", err
				}
				what := "Put " + name + " in the store"
				if had {
					what = "Changed the value of " + name
				}
				return what + ".", nil
			})
		},
	}
	cmd.Flags().BoolVar(&stdin, "stdin", false, "read the value from stdin, not from the terminal")
	return cmd
}

func newSecretRmCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "Take a secret out of the store",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			return cfg.changeStore(false, nil, func(s *store.Store) (string, error) {
				ok, err := s.Remove(name)
				switch {
				case err != nil:
					return "", err
				case !ok:
					return "", usage("the store holds no secret %s", name)
				}
				return "Took " + name + " out of the store.", nil
			})
		},
	}
}

// newSecretOriginsCmd returns vegtam secret allow, with allow, or vegtam
// secret deny.
func newSecretOriginsCmd(cfg *Config, allow bool) *cobra.Command {
	use, short, long := "allow", "Let a secret go to origins too",
		`Let the secret name go to the origins given too, each scheme://host, and
:port unless it is the scheme's own, such as https://api.example.com or
http://127.0.0.1:8080: never a wildcard. A secret goes to its origins
alone, and one bound to none goes nowhere.`
	if !allow {
		use, short, long = "deny", "Stop a secret from going to origins",
			`Stop the secret name from going to the origins given. One bound to none
goes nowhere.`
	}
	return &cobra.Command{
		Use:   use + " <name> <origin>...",
		Short: short,
		Long:  long,
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			name, origins := args[0], args[1:]
			return cfg.changeStore(false, nil, func(s *store.Store) (string, error) {
				if allow {
					return "", s.Allow(name, origins...)
				}
				return "", s.Deny(name, origins...)
			})
		},
	}
}

func newSecretImportCmd(cfg *Config) *cobra.Command {
	var envName string
	cmd := &cobra.Command{
		Use:   "import <http-client.private.env.json>",
		Short: "Put the values of a private environment file in the store",
		Long: `Put the values of a private environment file in the store: those of
$shared and of the environment -e names, which replace them name by name,
each with the origins the file's $allow binds it to. A value the store
holds already is replaced, and its origins with it. Without -e, the file
must define one environment besides $shared, or none. The file is not
changed: it still holds the values, and a private file beside the
requests is read before the store. Once the store holds them, delete the
file, or the values in it; until then, any process that runs as you can
read them, and the keeper does not use them.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return cfg.importSecrets(args[0], envName)
		},
	}
	cmd.Flags().StringVarP(&envName, "env", "e", "", "the environment whose values to take, over those of $shared")
	return cmd
}

// storeError returns err, of package store, as an error of the kind it
// is.
func storeError(err error) error {
	if _, ok := errors.AsType[*core.Error](err); ok {
		return err
	}
	kind := core.KindUsage
	if errors.Is(err, store.ErrCorrupt) || errors.Is(err, store.ErrVersion) {
		kind = core.KindParse
	}
	return core.Errorf(kind, core.Source{}, "%v", err)
}

// listStore returns the store as vegtam secret list prints it.
func listStore() (*output.Store, error) {
	path, err := store.Path()
	if err != nil {
		return nil, storeError(err)
	}
	doc := &output.Store{Path: path, Secrets: []output.StoreSecret{}}
	if doc.Exists, err = store.Exists(path); err != nil {
		return nil, storeError(err)
	} else if !doc.Exists {
		return doc, nil
	}
	origins, err := store.Origins(path)
	if err != nil {
		return nil, storeError(err)
	}
	for _, name := range slices.Sorted(maps.Keys(origins)) {
		doc.Secrets = append(doc.Secrets, output.StoreSecret{Name: name, Allowed: append([]string{}, origins[name]...)})
	}
	return doc, nil
}

// printStore prints doc, after what, a sentence that says what changed.
func (c *Config) printStore(doc *output.Store, what string) {
	if c.asJSON() {
		c.writeJSON(output.Document{SchemaVersion: output.SchemaVersion, Store: doc})
		return
	}
	var b strings.Builder
	if what != "" {
		b.WriteString(what + "\n")
	}
	switch {
	case !doc.Exists:
		fmt.Fprintf(&b, "No store of secrets at %s: vegtam secret set or import makes one.\n", doc.Path)
	case len(doc.Secrets) == 0:
		fmt.Fprintf(&b, "The store at %s holds no secret.\n", doc.Path)
	default:
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		for _, s := range doc.Secrets {
			fmt.Fprintf(tw, "%s\t%s\n", s.Name, or(strings.Join(s.Allowed, ", "), "bound to none: goes nowhere"))
		}
		tw.Flush()
	}
	fmt.Fprint(c.out, c.text(b.String()))
}

// secretValue returns the value of the secret name: typed at the
// terminal, or read from stdin.
func (c *Config) secretValue(name string, stdin bool) ([]byte, error) {
	if !stdin {
		v, err := c.readSecret("value of " + name + ": ")
		if err != nil {
			return nil, usage("the value of %s: %v", name, err)
		}
		return v, nil
	}
	if c.Stdin == nil {
		return nil, usage("--stdin: no stdin")
	}
	v, err := io.ReadAll(io.LimitReader(c.Stdin, maxSecret+1))
	switch {
	case err != nil:
		return nil, usage("--stdin: %v", err)
	case len(v) > maxSecret:
		clear(v)
		return nil, usage("--stdin: a value is at most %d MiB", maxSecret>>20)
	}
	v = bytes.TrimSuffix(v, []byte("\n"))
	return bytes.TrimSuffix(v, []byte("\r")), nil
}

// unlock opens the store at path with its password, typed at the
// terminal; with create, makes one if there is none, asking for its new
// password twice.
func (c *Config) unlock(path string, create bool) (*store.Store, error) {
	exists, err := store.Exists(path)
	switch {
	case err != nil:
		return nil, storeError(err)
	case !exists && !create:
		return nil, usage("no store of secrets at %s: vegtam secret set or import makes one", path)
	case !exists:
		return c.create(path)
	}
	pw, err := c.readSecret("password of the store of secrets (" + path + "): ")
	if err != nil {
		return nil, usage("the password: %v", err)
	}
	defer clear(pw)
	s, err := store.Open(path, pw)
	if err != nil {
		return nil, storeError(err)
	}
	return s, nil
}

// create makes a store at path, under a new password typed twice.
func (c *Config) create(path string) (*store.Store, error) {
	pw, err := c.readSecret("new password for the store of secrets (" + path + "): ")
	defer clear(pw)
	if err != nil {
		return nil, usage("the password: %v", err)
	}
	again, err := c.readSecret("the same again: ")
	defer clear(again)
	if err != nil {
		return nil, usage("the password: %v", err)
	}
	if !bytes.Equal(pw, again) {
		return nil, usage("the two passwords differ: the store is not made")
	}
	s, err := store.Create(path, pw)
	if err != nil {
		return nil, storeError(err)
	}
	return s, nil
}

// changeStore opens the store, or with create makes one, applies change,
// saves it, and prints it, after the sentence change returns, with what
// decorate adds to the document, if not nil.
func (c *Config) changeStore(create bool, decorate func(*output.Store), change func(*store.Store) (string, error)) error {
	path, err := store.Path()
	if err != nil {
		return storeError(err)
	}
	s, err := c.unlock(path, create)
	if err != nil {
		return err
	}
	defer s.Close()
	what, err := change(s)
	if err != nil {
		return storeError(err)
	}
	if err = s.Save(); err != nil {
		return storeError(err)
	}
	doc, err := listStore()
	if err != nil {
		return err
	}
	if decorate != nil {
		decorate(doc)
	}
	c.printStore(doc, what)
	return nil
}

// importSecrets puts the values of the private environment file at path,
// for the environment envName, in the store.
func (c *Config) importSecrets(path, envName string) error {
	if filepath.Base(path) != env.PrivateFile {
		return usage("%s: want a %s, whose values are secrets", path, env.PrivateFile)
	}
	p, envs, err := env.ReadPrivate(path, envName)
	if err != nil {
		return err
	}
	if envName == "" && len(envs) > 1 {
		return usage("%s defines %s: choose one with -e", path, strings.Join(envs, ", "))
	}
	if envName == "" && len(envs) == 1 {
		envName = envs[0]
		if p, _, err = env.ReadPrivate(path, envName); err != nil {
			return err
		}
	}
	if len(p.Values) == 0 {
		return usage("%s holds no value for %s", path, or(envName, "$shared"))
	}
	c.printWarnings(output.Warnings(p.Warnings, nil))
	names := slices.Sorted(maps.Keys(p.Values))
	from := path + " (" + or(envName, "$shared") + ")"
	decorate := func(doc *output.Store) { doc.Imported, doc.From = names, from }
	return c.changeStore(true, decorate, func(s *store.Store) (string, error) {
		for _, name := range names {
			if old, ok := s.Get(name); ok {
				if err := s.Deny(name, old.Origins...); err != nil {
					return "", err
				}
			}
			if err := s.Set(name, p.Values[name]); err != nil {
				return "", err
			}
			if origins := p.Allow[name]; len(origins) > 0 {
				if err := s.Allow(name, origins...); err != nil {
					return "", err
				}
			}
		}
		return fmt.Sprintf("Put %d secrets of %s in the store: %s.\n"+
			"The file still holds them, and a private file beside the requests is read before the store: once you no longer need it, "+
			"delete it, or the values in it. Until then any process that runs as you can read them, and the keeper does not use them.",
			len(names), from, strings.Join(names, ", ")), nil
	})
}
