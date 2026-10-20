package cli

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/history"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
)

func newDescribeCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "describe",
		Short: "Print what a program needs to know to run vegtam",
		Long: `Print, in one document, what a program needs to know to run vegtam:
the version; the commands and their flags; the exit codes and the kinds
of error; whether a person is at a terminal, and why; the operator's
policy and what of it applies to this mode, as vegtam policy prints it;
what vegtam never does, whoever asks; where the JSON Schema and the
history of runs are. JSON when stdout is not a terminal or with --json,
text otherwise; docs/AUTOMATION.md is the contract it summarises.

A policy file that cannot be read does not stop it: the document says
why in policy_error, in place of policy, and the exit code is 6, as
every command that reads the policy would give.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d := cfg.describe(cmd.Root())
			if cfg.asJSON() {
				cfg.writeJSON(output.Document{SchemaVersion: output.SchemaVersion, Describe: d})
			} else {
				fmt.Fprint(cfg.out, cfg.text(describeText(d)))
			}
			if d.PolicyError != nil {
				cfg.printError(d.PolicyError)
				return &exitError{exitPolicy}
			}
			return nil
		},
	}
}

// errorKinds are the kinds of error and their causes; exitCode gives
// their exit codes.
var errorKinds = []struct {
	kind    core.Kind
	meaning string
}{
	{core.KindAssert, "an @assert failed; the response is in the result"},
	{core.KindUsage, "bad arguments, a missing file, an unknown request or environment"},
	{core.KindParse, "a .http or environment file outside the supported format"},
	{core.KindVariable, "a placeholder without a value, or a {{$cmd NAME}} that failed"},
	{core.KindRequest, "a resolved request that cannot be sent: URL, header, body file"},
	{core.KindImport, "an export that cannot be read"},
	{core.KindCapture, "an @capture found no value"},
	{core.KindNetwork, "DNS, connection, TLS, redirects"},
	{core.KindTimeout, "a time limit ran out; timeout_phase says which"},
	{core.KindStatus, "HTTP status 400 or above, with --fail"},
	{core.KindConfirm, "a request not sent without --confirm: one with an @note, or, without a person at a terminal, " +
		"one whose method is not GET, HEAD or OPTIONS; error.confirm says what confirms it. Ask a person first"},
	{core.KindPolicy, "not allowed: a command file that is not trusted, an address vegtam never connects to or that " +
		"the policy does not allow, a policy file that cannot be read. Ask a person; do not work around it"},
	{core.KindCanceled, "SIGINT or SIGTERM came while a request or a command ran"},
}

// never is what vegtam never does, whoever asks. Each is held by the
// code, and by its tests.
var never = []string{
	"connect to the metadata services of clouds, or to link-local, multicast or unspecified addresses (vegtam policy lists them)",
	"print a request or a response as it went on the wire: requests show secrets as their placeholders, " +
		"and a secret value anywhere else, in text or JSON, on stdout or stderr, is masked as ***",
	"write a secret value it reads or captures to a file: the history of runs keeps no header, body or value, and cookies " +
		"stay in memory; the only files vegtam writes are the history, the trust store (vegtam trust) and those of import",
	"read its policy from anywhere but $XDG_CONFIG_HOME/vegtam/policy.json, or ~/.config/vegtam/policy.json: " +
		"not from a directory of .http files, nor the current one",
	"take a proxy, an address to connect to, a CA, a client certificate or an unchecked certificate from a .http or environment file",
	"run a {{$cmd NAME}} whose command file a person has not trusted, or that has changed since",
	`send without --confirm a request with "# @note", or, with no person at a terminal, one whose method is not GET, HEAD or ` +
		`OPTIONS; the operator's policy may lift the second, network.confirm "never", and nothing lifts the first`,
	"follow a redirect from https to http, or carry Authorization, Cookie, Proxy-Authorization or a header that holds a secret to another origin",
	"send the proxy's credentials anywhere but to the proxy",
	"open the terminal interface, or wait for a key, without a terminal",
}

// describe returns what vegtam describe prints, for the command line
// root.
func (c *Config) describe(root *cobra.Command) *output.Describe {
	d := &output.Describe{
		Name: "vegtam", Version: c.Version, Commands: describeCommands(root), Flags: describeFlags(root.PersistentFlags()),
		Never: never, Schema: "vegtam schema",
	}
	d.Mode.Unattended, d.Mode.Why = c.mode()
	for _, e := range exitCodes {
		d.ExitCodes = append(d.ExitCodes, output.DescribeExit{Code: e.code, Meaning: e.meaning})
	}
	for _, e := range errorKinds {
		d.Errors = append(d.Errors, output.DescribeError{Kind: string(e.kind), ExitCode: exitCode(e.kind), Meaning: e.meaning})
	}
	if pol, err := c.loadPolicy(); err != nil {
		d.PolicyError = output.NewError(err, c.masker)
	} else {
		d.Policy = c.policyDoc(pol)
	}
	switch dir, err := policy.HistoryDir(); {
	case err != nil:
		d.History.Why = "no place for it: " + err.Error()
	case dir == "":
		d.History.Why = "VEGTAM_NO_HISTORY is set"
	default:
		d.History.On, d.History.Path = true, filepath.Join(dir, history.FileName)
	}
	return d
}

// mode reports whether no person is at a terminal, and why.
func (c *Config) mode() (unattended bool, why string) {
	switch {
	case c.json:
		return true, "--json is given"
	case !c.Interactive:
		return true, "stdin or stdout is not a terminal"
	}
	return false, "stdin and stdout are terminals"
}

// describeCommands returns the commands below c that run something, and
// their flags, but for those cobra adds of its own: help and completion.
func describeCommands(c *cobra.Command) []output.DescribeCommand {
	var out []output.DescribeCommand
	for _, sub := range c.Commands() {
		if sub.Hidden || sub.Deprecated != "" || sub.Name() == "help" || sub.Name() == "completion" {
			continue
		}
		if sub.Runnable() {
			name := strings.TrimPrefix(sub.CommandPath(), c.Root().Name()+" ")
			out = append(out, output.DescribeCommand{
				Name: name, Usage: c.CommandPath() + " " + sub.Use, Summary: sub.Short, Flags: describeFlags(sub.LocalNonPersistentFlags()),
			})
		}
		out = append(out, describeCommands(sub)...)
	}
	return out
}

// describeFlags returns the flags of fs, but for hidden and deprecated
// ones and --help.
func describeFlags(fs *pflag.FlagSet) []output.DescribeFlag {
	out := []output.DescribeFlag{}
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Hidden || f.Deprecated != "" || f.Name == "help" {
			return
		}
		d := output.DescribeFlag{Name: "--" + f.Name, Value: "required", Type: f.Value.Type(), Usage: f.Usage}
		switch {
		case f.Value.Type() == "bool":
			d.Value, d.Type = "none", ""
		case f.NoOptDefVal != "":
			d.Value = "optional"
		}
		if f.Shorthand != "" {
			d.Shorthand = "-" + f.Shorthand
		}
		if v := f.DefValue; v != "" && v != "false" && v != "[]" {
			d.Default = v
		}
		out = append(out, d)
	})
	return out
}

// describeText returns d as text for a person.
func describeText(d *output.Describe) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n\n", d.Name, d.Version)
	who := "a person is at a terminal"
	if d.Mode.Unattended {
		who = "no person is at a terminal"
	}
	fmt.Fprintf(&b, "Mode: %s (%s).\n\nCommands:\n", who, d.Mode.Why)
	flags := func(fs []output.DescribeFlag) {
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		for _, f := range fs {
			name := f.Name
			if f.Shorthand != "" {
				name = f.Shorthand + ", " + name
			}
			switch f.Value {
			case "required":
				name += " " + f.Type
			case "optional":
				name += "[=...]"
			}
			usage := f.Usage
			if f.Default != "" {
				usage += " (default " + f.Default + ")"
			}
			fmt.Fprintf(tw, "      %s\t%s\n", name, usage)
		}
		tw.Flush()
	}
	for _, c := range d.Commands {
		fmt.Fprintf(&b, "  %s\n    %s\n", c.Usage, c.Summary)
		flags(c.Flags)
	}
	b.WriteString("  Every command:\n")
	flags(d.Flags)
	b.WriteString("\nExit codes:\n")
	for _, e := range d.ExitCodes {
		b.WriteString(wrap(fmt.Sprintf("  %d  ", e.Code), e.Meaning) + "\n")
	}
	b.WriteString("\nErrors:\n")
	for _, e := range d.Errors {
		b.WriteString(wrap(fmt.Sprintf("  %-9s %3s  ", e.Kind, strconv.Itoa(e.ExitCode)), e.Meaning) + "\n")
	}
	b.WriteString("\nPolicy:\n")
	if d.Policy != nil {
		for line := range strings.Lines(policyText(d.Policy)) {
			if line != "\n" {
				line = "  " + line
			}
			b.WriteString(line)
		}
	} else {
		fmt.Fprintf(&b, "  cannot be read: %s\n", d.PolicyError.Message)
	}
	b.WriteString("\nvegtam never, whoever asks:\n")
	for _, n := range d.Never {
		b.WriteString(wrap("  - ", n) + "\n")
	}
	fmt.Fprintf(&b, "\nSchema: %s prints the JSON Schema of the JSON output.\n", d.Schema)
	if d.History.On {
		fmt.Fprintf(&b, "History: %s\n", d.History.Path)
	} else {
		fmt.Fprintf(&b, "History: off: %s\n", d.History.Why)
	}
	return b.String()
}
