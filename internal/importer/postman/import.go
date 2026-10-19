package postman

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vidforull/vegtam/internal/core"
	"github.com/vidforull/vegtam/internal/core/env"
	"github.com/vidforull/vegtam/internal/core/output"
)

// Result is what an import produces: the files to write and the report.
type Result struct {
	Files  []File
	Report *output.Import
}

// File is a file to write.
type File struct {
	Path    string // relative to the output directory, slash-separated
	Data    []byte
	Private bool // holds secret values: readable by its owner only
}

// importer is the state of one import.
type importer struct {
	src, out string
	report   *output.Import
	cols     []*collection
	globals  []param
	envs     []environment
	envNames names
	dirs     names           // collection directories
	secret   map[string]bool // variables whose values are secrets, across the export
	renamed  map[string]bool // Postman variable names reported as renamed
	nested   map[string]bool // variables reported for placeholders in their values
	convs    []*converter
	files    []File
}

// environment is a Postman environment, under its new name.
type environment struct {
	name string
	vars []param
}

// Import converts the Postman export at src, a collection file or a
// directory with collections, environments and globals, into .http and
// environment files for the directory out. It writes nothing: the caller
// writes Result.Files. Paths in the report start with out.
func Import(src, out string) (*Result, error) {
	imp := &importer{
		src: src, out: out, envNames: names{}, dirs: names{}, secret: map[string]bool{}, renamed: map[string]bool{}, nested: map[string]bool{},
		report: &output.Import{
			Source: src, Output: out, Environments: []string{}, Files: []string{},
			Skipped: []output.Skipped{}, Variables: []output.ImportVariable{},
		},
	}
	if err := imp.load(); err != nil {
		return nil, err
	}
	if len(imp.envs) == 0 {
		// -e needs an environment to select, even if every variable is
		// in $shared.
		imp.envs = []environment{{name: "default"}}
	}
	for _, e := range imp.envs {
		imp.report.Environments = append(imp.report.Environments, e.name)
	}
	for _, col := range imp.cols {
		imp.collection(col)
	}
	vars := map[[2]string]*output.ImportVariable{}
	for _, c := range imp.convs {
		imp.envFiles(c, vars)
	}
	for _, k := range slices.SortedFunc(maps.Keys(vars), func(a, b [2]string) int { return strings.Compare(a[0]+"\x00"+a[1], b[0]+"\x00"+b[1]) }) {
		imp.report.Variables = append(imp.report.Variables, *vars[k])
	}
	slices.SortFunc(imp.files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	for _, f := range imp.files {
		if !filepath.IsLocal(filepath.FromSlash(f.Path)) {
			return nil, fmt.Errorf("internal error: output path %q is outside the output directory", f.Path)
		}
		imp.report.Files = append(imp.report.Files, imp.at(f.Path))
	}
	return &Result{Files: imp.files, Report: imp.report}, nil
}

func importErrorf(path, format string, args ...any) error {
	return core.Errorf(core.KindImport, core.Source{File: path}, format, args...)
}

// load reads the export: one collection file, or every .json file below
// a directory, in name order.
func (imp *importer) load() error {
	fi, err := os.Stat(imp.src)
	if err != nil {
		return core.Errorf(core.KindUsage, core.Source{}, "%v", err)
	}
	if !fi.IsDir() {
		var v any
		v, err = readFile(imp.src)
		if err != nil {
			return importErrorf(imp.src, "%v", err)
		}
		col, ok := v.(*collection)
		if !ok {
			return importErrorf(imp.src, "not a Postman collection; to import environments too, pass the directory of the export")
		}
		imp.cols = append(imp.cols, col)
		return nil
	}
	err = filepath.WalkDir(imp.src, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && path != imp.src && strings.HasPrefix(d.Name(), "."):
			return filepath.SkipDir
		case d.IsDir() || filepath.Ext(path) != ".json":
			return nil
		}
		v, err := readFile(path)
		switch v := v.(type) {
		case *collection:
			imp.cols = append(imp.cols, v)
		case *vars:
			if v.Scope == "globals" {
				imp.globals = append(imp.globals, imp.variables(v.Values)...)
				break
			}
			imp.envs = append(imp.envs, environment{name: imp.envNames.unique(slug(v.Name, "env")), vars: imp.variables(v.Values)})
		default:
			imp.skip("file", err.Error(), path)
		}
		return nil
	})
	if err != nil {
		return core.Errorf(core.KindUsage, core.Source{}, "%v", err)
	}
	if len(imp.cols) == 0 {
		return importErrorf(imp.src, "no Postman collections (v2.0 or v2.1) found")
	}
	return nil
}

var errUnknownFile = errors.New("not a Postman collection, environment or globals file")

// readFile reads a Postman file: a *collection, or *vars for an
// environment or the globals.
func readFile(path string) (any, error) {
	data, err := os.ReadFile(path) //nolint:forbidigo,gosec // G304: an export named on the command line, or found below a directory named there
	if err != nil {
		return nil, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	switch {
	case probe["info"] != nil && probe["item"] != nil:
		var c collection
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("collection: %w", err)
		}
		return &c, nil
	case probe["values"] != nil:
		var v vars
		if err := json.Unmarshal(data, &v); err != nil {
			return nil, fmt.Errorf("environment: %w", err)
		}
		return &v, nil
	}
	return nil, errUnknownFile
}

// variables returns the enabled variables of ps under vegtam names, and
// notes which hold secrets.
func (imp *importer) variables(ps []param) []param {
	var vs []param
	for _, p := range ps {
		if p.off() || p.Key == "" {
			continue
		}
		name := imp.rename(string(p.Key))
		if p.Type == "secret" || p.Secret || secretName(name) {
			imp.secret[name] = true
		}
		vs = append(vs, param{Key: text(name), Value: p.Value})
	}
	return vs
}

// rename returns the vegtam name of the Postman variable name, reporting
// a change once.
func (imp *importer) rename(name string) string {
	v := variable(name)
	if v != name && !imp.renamed[name] {
		imp.renamed[name] = true
		imp.skip("variable", fmt.Sprintf("variable %q is renamed %s", name, v), imp.out)
	}
	return v
}

func (imp *importer) skip(category, reason, where string) {
	imp.report.Skipped = append(imp.report.Skipped, output.Skipped{Category: category, Reason: reason, Where: where})
}

// at returns the path of rel, a path under the output directory.
func (imp *importer) at(rel string) string { return filepath.Join(imp.out, filepath.FromSlash(rel)) }

func (imp *importer) write(rel string, data []byte, private bool) {
	imp.files = append(imp.files, File{Path: rel, Data: data, Private: private})
}

// envFiles writes the environment files of the collection of c and notes
// in vars the variables its requests use that need a look: secrets, and
// variables without a value.
//
// A collection's directory gets both files, with every environment in
// them: vegtam reads the nearest file of each kind, so files higher up
// would not add to these. Globals and collection variables go to $shared,
// collection variables last, as Postman ranks them. A variable is secret
// or not across the whole export, so all its values are in one file and
// precedence within the file holds.
func (imp *importer) envFiles(c *converter, vars map[[2]string]*output.ImportVariable) {
	type envMap map[string]map[string]string
	public, private := envMap{}, envMap{}
	defined := map[string]bool{}
	add := func(env string, ps []param) {
		for _, p := range ps {
			name := string(p.Key)
			if r := refs(string(p.Value)); len(r) > 0 && !imp.nested[name] {
				imp.nested[name] = true
				imp.skip("variable", fmt.Sprintf("the value of %s refers to {{%s}}, but vegtam does not resolve placeholders in values",
					name, strings.Join(r, "}}, {{")), imp.out)
			}
			m := public
			if imp.secret[name] {
				m = private
			}
			if m[env] == nil {
				m[env] = map[string]string{}
			}
			m[env][name] = string(p.Value)
			defined[name] = true
		}
	}
	add("$shared", imp.globals)
	add("$shared", c.vars)
	add("$shared", c.created)
	for _, e := range imp.envs {
		if public[e.name] == nil {
			public[e.name] = map[string]string{}
		}
		add(e.name, e.vars)
	}
	publicPath, privatePath := c.dir+"/"+env.PublicFile, c.dir+"/"+env.PrivateFile
	// The private file is written even if empty: else a private file
	// further up would take its place.
	imp.write(publicPath, marshal(public), false)
	imp.write(privatePath, marshal(private), true)
	for _, name := range slices.Sorted(maps.Keys(c.used)) {
		status, file := "secret", privatePath
		switch {
		case !defined[name]:
			status = "unset"
			if !imp.secret[name] {
				file = publicPath
			}
		case !imp.secret[name]:
			continue
		}
		v := vars[[2]string{name, status}]
		if v == nil {
			v = &output.ImportVariable{Name: name, Status: status}
			vars[[2]string{name, status}] = v
		}
		v.Files = append(v.Files, imp.at(file))
	}
}

// marshal returns v as indented JSON, with <, > and & as they are.
func marshal(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v) // maps of strings always encode
	return b.Bytes()
}
