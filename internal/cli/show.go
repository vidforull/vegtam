package cli

import (
	"fmt"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/httpfile"
	"github.com/vidforull/vegtam/internal/core/output"
	"github.com/vidforull/vegtam/internal/core/policy"
	"github.com/vidforull/vegtam/internal/core/session"
)

func newShowCmd(cfg *Config) *cobra.Command {
	var envName string
	cmd := &cobra.Command{
		Use:   "show <file>#<name>|<N>",
		Short: "Print a request without sending it",
		Long: `Print a request without sending it. With -e it is resolved for that
environment and shown as it would go on the wire; without -e it is shown
as written. Secrets appear as their placeholders, such as {{token}}. A
{{$cmd NAME}} is checked against the trust store, with exit code 6 if
its command file is not trusted, but its command does not run.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, i, err := parseTarget(args[0]).request()
			if err != nil {
				return err
			}
			res := &output.Result{Ref: output.Ref(f, i), Request: output.Written(f.Requests[i])}
			if envName != "" {
				s := session.New(session.Options{Env: envName, DryRun: true, Trust: policy.DefaultStore()})
				cfg.secrets = s.Masker
				j := s.Prepare(cmd.Context(), f, i)
				cfg.masker = s.Masker()
				if j.Err != nil {
					return j.Err
				}
				res.Request = output.Sent(j.Prepared, cfg.masker)
			}
			if cfg.asJSON() {
				cfg.writeJSON(output.Document{SchemaVersion: output.SchemaVersion, Result: res})
				return nil
			}
			var b strings.Builder
			output.WriteRequest(&b, res.Request)
			fmt.Fprint(cfg.out, printable(b.String()))
			return nil
		},
	}
	cmd.Flags().StringVarP(&envName, "env", "e", "", "resolve the request for this environment")
	return cmd
}

func newListCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "list <file>|<dir>",
		Short: "List the requests of .http files",
		Long: `List the requests of a .http file, or of the .http files in a directory
and below it: how to refer to each, its method and URL as written, and
its directives. Files that do not parse are reported, the rest listed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			paths, err := httpfile.Files(args[0])
			if err != nil {
				return err
			}
			doc := output.Document{SchemaVersion: output.SchemaVersion, Requests: []*output.Listed{}}
			for _, path := range paths {
				f, err := httpfile.ParseFile(path)
				if err != nil {
					e := output.NewError(err, cfg.masker)
					cfg.printError(e)
					if doc.Result == nil {
						doc.Result = &output.Result{Error: e}
					}
					continue
				}
				doc.Requests = append(doc.Requests, output.List(f)...)
			}
			if cfg.asJSON() {
				cfg.writeJSON(doc)
			} else {
				var b strings.Builder
				tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "REF\tMETHOD\tURL\tDIRECTIVES")
				for _, l := range doc.Requests {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", l.Ref, l.Method, l.URL, directives(l.Directives))
				}
				tw.Flush()
				fmt.Fprint(cfg.out, printable(trailingSpace.ReplaceAllString(b.String(), "")))
			}
			if doc.Result != nil {
				return &exitError{exitCode(core.KindParse)}
			}
			return nil
		},
	}
}

// trailingSpace is the padding tabwriter leaves before an empty last
// column.
var trailingSpace = regexp.MustCompile(`(?m) +$`)

// directives summarises ds: how many asserts and captures, and the tags.
func directives(ds []output.Directive) string {
	count := map[string]int{}
	var tags []string
	for _, d := range ds {
		count[d.Kind]++
		if d.Kind == "tag" {
			tags = append(tags, d.Value)
		}
	}
	var parts []string
	for _, kind := range []string{"assert", "capture"} {
		if n := count[kind]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d @%s", n, kind))
		}
	}
	if len(tags) > 0 {
		parts = append(parts, "@tag "+strings.Join(tags, " "))
	}
	return strings.Join(parts, ", ")
}

func newSchemaCmd(cfg *Config) *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Print the JSON Schema of the JSON output",
		Long: `Print the JSON Schema (draft 2020-12) of the JSON documents that run,
show, list, import and trust print. Fields are only ever added; schema_version
changes if one has to change its meaning or go away.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			fmt.Fprint(cfg.out, output.Schema)
			return nil
		},
	}
}
