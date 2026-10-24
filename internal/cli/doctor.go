package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
	"github.com/vidforull/vegtam/internal/keeper"
)

func newDoctorCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Print where the secrets are and who else can read them",
		Long: `Print where the secrets that vegtam would send from here are kept,
and who besides you can read them or act for you: names, paths and
permission bits, never a value. doctor reads no secret, neither the
private environment file nor the value of a variable. Its exit code is
0 whatever it finds, a policy file that cannot be read too: it says why.

mode is whether a person is at a terminal, and why: stdin and stdout
are terminals and --json is not given. A run without a person gets no
secret value, or sends the requests that need one through the keeper,
as the policy says.

policy is the operator's policy file (see vegtam policy --help), found
or not, or why it cannot be read; unattended and keeper asks are its
secrets.unattended and secrets.keeper_asks as they apply, the defaults
if it does not give them; binds names the {{$env NAME}} and
{{$cmd NAME}} it binds to origins.

private file is the nearest http-client.private.env.json from the
current directory upwards, as a run of a .http file here finds it, with
its permission bits and owner. Any process that runs as your user can
read it, agents started from this shell among them. environment names
the variables of the policy's {{$env NAME}} and network.proxy_auth that
hold a value here: every process started from this shell inherits them.

keeper is the unix socket of the keeper, a process you run in your
terminal to hold the secrets, and what is at it:
$XDG_RUNTIME_DIR/vegtam/keeper.sock, or keeper.sock in vegtam's
directory of your cache, ~/.cache/vegtam or ~/Library/Caches/vegtam on
macOS: whether a keeper of yours answers there, its pid, and the
terminal multiplexer it runs in, if it does.

multiplexer is tmux or screen, when TMUX or STY says that this shell
runs in one: another process can read and type into a session of a
multiplexer, and so read what vegtam shows there and answer what it
asks.

config is vegtam's configuration directory, that of the policy and the
trust store, with its permission bits; policy gives those of the policy
file. If others can write either, the policy is not read; if others can
read the policy, they learn what vegtam may do.

The warnings come last, one to a line.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d := cfg.doctor(cmd.Context())
			if cfg.asJSON() {
				cfg.writeJSON(output.Document{SchemaVersion: output.SchemaVersion, Doctor: d})
				return nil
			}
			fmt.Fprint(cfg.out, cfg.text(doctorText(d)))
			return nil
		},
	}
}

// doctor returns what vegtam doctor prints. It reads no secret: of the
// private environment file its mode and owner, of a variable whether it
// holds a value.
func (c *Config) doctor(ctx context.Context) *output.Doctor {
	d := &output.Doctor{}
	d.Mode.Unattended, d.Mode.Why = c.mode()
	// The configuration directory first: the policy file is in it.
	var dir, file seen
	if path, err := policy.ConfigDir(); err != nil {
		dir.Why = "there is no place for it: " + err.Error()
		file.Why = dir.Why
	} else {
		dir, file = lookAt(path), lookAt(filepath.Join(path, policy.PolicyFile))
	}
	d.Config.Dir, d.Config.Policy = dir.DoctorPath, file.DoctorPath
	pol := doctorPolicy(d, c.masker)
	d.Mode.Secrets = runSecrets(d.Mode.Unattended, pol)
	doctorSecrets(d, pol)
	doctorKeeper(ctx, d)
	for _, m := range multiplexers {
		if env.Has(m.Variable) {
			d.Multiplexers = append(d.Multiplexers, m)
			warn(d, "", "this shell runs in %s (%s is set): another process can read and type into a session of a multiplexer, "+
				"and so read what vegtam shows there and answer what it asks", m.Name, m.Variable)
		}
	}
	doctorConfig(d, dir, file)
	return d
}

// multiplexers are the terminal multiplexers that doctor knows a shell to
// run in, by the variable each sets in it.
var multiplexers = []output.DoctorMultiplexer{{Name: "tmux", Variable: "TMUX"}, {Name: "screen", Variable: "STY"}}

// warn adds a warning of file, or of none, to d.
func warn(d *output.Doctor, file, format string, args ...any) {
	d.Warnings = append(d.Warnings, output.Warning{Message: fmt.Sprintf(format, args...), File: file})
}

// doctorPolicy sets what the operator's policy says of secrets, and
// returns it; nil if it cannot be read, which d then says, with every
// secret value hidden by m.
func doctorPolicy(d *output.Doctor, m *core.Masker) *policy.Policy {
	p := &d.Policy
	p.Path, p.Found = d.Config.Policy.Path, d.Config.Policy.Exists
	pol, err := policy.Load()
	if err != nil {
		p.Error = output.NewError(err, m)
		return nil
	}
	mode := output.NewSecretsMode(pol.Secrets)
	p.SecretsMode = &mode
	p.Env, p.Cmd = slices.Sorted(maps.Keys(pol.Secrets.Env)), slices.Sorted(maps.Keys(pol.Secrets.Cmd))
	return pol
}

// doctorSecrets sets where the secrets of the current directory are, by
// the private environment file and by the variables of pol, and warns of
// each place that holds them.
func doctorSecrets(d *output.Doctor, pol *policy.Policy) {
	s := &d.Secrets
	if dir, err := os.Getwd(); err != nil {
		warn(d, "", "the current directory cannot be told, nor so its private environment file: %v", err)
	} else {
		s.Dir = dir
		doctorPrivateFile(d, dir)
	}
	if pol == nil {
		return
	}
	names := slices.Collect(maps.Keys(pol.Secrets.Env))
	if pol.Network.ProxyAuth != "" {
		names = append(names, pol.Network.ProxyAuth)
	}
	slices.Sort(names)
	for _, name := range slices.Compact(names) {
		if env.Has(name) {
			s.Environment = append(s.Environment, name)
			warn(d, "", "%s is set in the environment, which every process started from this shell inherits, agents among them", name)
		}
	}
}

// doctorPrivateFile sets the private environment file that the requests
// of the .http files in dir would read, if there is one, and warns of it:
// whoever runs as the user reads it.
func doctorPrivateFile(d *output.Doctor, dir string) {
	path := env.Nearest(dir, env.PrivateFile)
	if path == "" {
		return
	}
	f := lookAt(path)
	d.Secrets.PrivateFile = &f.DoctorPath
	warn(d, path, "its secrets can be read by any process that runs as your user, agents started from this shell among them")
	switch {
	case f.perm&0o022 != 0:
		warn(d, path, "others can write it, and so change its secrets and where they go: chmod 600 %s", path)
	case f.perm&0o044 != 0:
		warn(d, path, "others can read it too: chmod 600 %s", path)
	}
}

// doctorKeeper sets where the keeper listens and what is there.
func doctorKeeper(ctx context.Context, d *output.Doctor) {
	k := &d.Keeper
	path, err := policy.KeeperSocket()
	if err != nil {
		k.Socket.Why, k.Why = "there is no place for it: "+err.Error(), "there is no place for the socket"
		return
	}
	k.Socket = lookAt(path).DoctorPath
	switch s := k.Socket; {
	case s.Why != "":
		k.Why = "the socket cannot be looked at"
	case !s.Exists:
		k.Why = "nothing is at the socket"
	case s.Type != output.PathSocket:
		k.Why = "what is at the path is not a socket"
	case !s.Owned:
		k.Why = "the socket belongs to another user"
		warn(d, path, "the keeper's socket belongs to another user: whatever answers on it is not your keeper")
	default:
		dctx, cancel := context.WithTimeout(ctx, keeperDial)
		defer cancel()
		c, err := keeper.Dial(dctx, path)
		if err != nil {
			k.Why = err.Error()
			return
		}
		k.Running = true
		k.PID, k.Multiplexer = c.Keeper()
		if err := c.Close(); err != nil {
			k.Why = err.Error()
		}
		if k.Multiplexer != "" {
			warn(d, path, "the keeper runs in %s: another process can read what it shows and type the codes it asks for", k.Multiplexer)
		}
	}
}

// keeperDial is how long doctor waits for the keeper to answer.
const keeperDial = 2 * time.Second

// doctorConfig warns of vegtam's configuration directory dir and of the
// policy file in it when another user owns them, or others can write
// them; and when others can read the policy.
func doctorConfig(d *output.Doctor, dir, file seen) {
	switch {
	case !dir.Exists:
	case !dir.Owned:
		warn(d, dir.Path, "it belongs to another user, so neither the policy nor the trust store in it is read")
	case dir.perm&0o022 != 0:
		warn(d, dir.Path, "others can write it, so neither the policy nor the trust store in it is read; make it private: chmod 700 %s", dir.Path)
	}
	switch {
	case !file.Exists:
	case !file.Owned:
		warn(d, file.Path, "it belongs to another user, so the policy is not read")
	case file.perm&0o022 != 0:
		warn(d, file.Path, "others can write it, so the policy is not read; make it private: chmod 600 %s", file.Path)
	case file.perm&0o044 != 0:
		warn(d, file.Path, "others can read the policy; it holds no secret, but says what vegtam may do: chmod 600 %s", file.Path)
	}
}

// seen is what lookAt found at a path, with its permission bits.
type seen struct {
	output.DoctorPath
	perm fs.FileMode
}

// lookAt returns what is at path, following links as reading it would;
// never what is in it.
func lookAt(path string) seen {
	s := seen{Path: path}
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s
	} else if pe, ok := errors.AsType[*fs.PathError](err); ok {
		s.Why = pe.Err.Error() // not "stat <path>: "
		return s
	} else if err != nil {
		s.Why = err.Error()
		return s
	}
	s.Exists, s.Owned, s.perm = true, policy.OwnedByUser(fi), fi.Mode().Perm()
	s.Mode = fmt.Sprintf("%04o", s.perm)
	if uid, ok := policy.Owner(fi); ok {
		s.UID = &uid
	}
	switch t := fi.Mode().Type(); {
	case t.IsRegular():
		s.Type = output.PathFile
	case t.IsDir():
		s.Type = output.PathDir
	case t&fs.ModeSocket != 0:
		s.Type = output.PathSocket
	default:
		s.Type = output.PathOther
	}
	return s
}

// doctorText returns d as text: a row for each part, then the warnings.
func doctorText(d *output.Doctor) string {
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	who := "a person is at a terminal"
	if d.Mode.Unattended {
		who = "no person is at a terminal"
	}
	fmt.Fprintf(tw, "mode\t%s (%s)\n", who, d.Mode.Why)
	switch p := d.Policy; {
	case p.Path == "":
		fmt.Fprintln(tw, "policy\tnone: there is no place for it")
	case p.Error == nil && !p.Found:
		fmt.Fprintf(tw, "policy\t%s, not found: vegtam does what it does on its own\n", p.Path)
	default:
		fmt.Fprintf(tw, "policy\t%s\n", pathText(d.Config.Policy))
	}
	if e := d.Policy.Error; e != nil {
		fmt.Fprintf(tw, "\tcannot be read: %s\n", e.Message)
	}
	if m := d.Policy.SecretsMode; m != nil {
		fmt.Fprintf(tw, "unattended\t%s\n", m.Unattended)
		fmt.Fprintf(tw, "keeper asks\t%s\n", m.KeeperAsks)
		fmt.Fprintf(tw, "binds\t%s\n", bindsText(d.Policy.Env, d.Policy.Cmd))
	}
	switch s := d.Secrets; {
	case s.PrivateFile != nil:
		fmt.Fprintf(tw, "private file\t%s\n", pathText(*s.PrivateFile))
	case s.Dir != "":
		fmt.Fprintf(tw, "private file\tnone in %s or above\n", s.Dir)
	}
	if names := d.Secrets.Environment; len(names) > 0 {
		fmt.Fprintf(tw, "environment\tholds %s\n", strings.Join(names, ", "))
	}
	keeper := pathText(d.Keeper.Socket)
	switch k := d.Keeper; {
	case k.Running && k.Multiplexer != "":
		keeper += fmt.Sprintf("; a keeper answers, pid %d, in %s", k.PID, k.Multiplexer)
	case k.Running:
		keeper += fmt.Sprintf("; a keeper answers, pid %d", k.PID)
	case k.Socket.Exists:
		keeper += "; " + k.Why
	}
	fmt.Fprintf(tw, "keeper\t%s\n", keeper)
	for _, m := range d.Multiplexers {
		fmt.Fprintf(tw, "multiplexer\t%s (%s is set)\n", m.Name, m.Variable)
	}
	fmt.Fprintf(tw, "config\t%s\n", pathText(d.Config.Dir))
	tw.Flush()
	b.WriteString("\n")
	if len(d.Warnings) == 0 {
		b.WriteString("Nothing to warn of.\n")
	}
	for _, w := range d.Warnings {
		if w.File != "" {
			fmt.Fprintf(&b, "warning: %s: %s\n", w.File, w.Message)
		} else {
			fmt.Fprintf(&b, "warning: %s\n", w.Message)
		}
	}
	return b.String()
}

// pathText says what p found at its path, for a row of doctorText.
func pathText(p output.DoctorPath) string {
	switch {
	case p.Path == "":
		return "none: " + p.Why
	case p.Why != "":
		return p.Path + ": " + p.Why
	case !p.Exists:
		return p.Path + ": nothing is there"
	}
	owner := "not yours"
	switch {
	case p.Owned:
		owner = "yours"
	case p.UID != nil:
		owner = "user " + strconv.Itoa(*p.UID) + "'s"
	}
	return fmt.Sprintf("%s: %s %s, %s", p.Path, p.Type, p.Mode, owner)
}

// bindsText says which {{$env NAME}} and {{$cmd NAME}} the policy binds,
// by their NAMEs.
func bindsText(envNames, cmdNames []string) string {
	var parts []string
	for _, c := range []struct {
		fn    string
		names []string
	}{{"$env", envNames}, {"$cmd", cmdNames}} {
		if len(c.names) > 0 {
			parts = append(parts, fmt.Sprintf("%d {{%s NAME}}: %s", len(c.names), c.fn, strings.Join(c.names, ", ")))
		}
	}
	if len(parts) == 0 {
		return "no {{$env NAME}} or {{$cmd NAME}}: their values go nowhere"
	}
	return strings.Join(parts, "; ")
}
