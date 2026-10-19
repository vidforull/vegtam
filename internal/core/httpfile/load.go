package httpfile

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/vidforull/vegtam/internal/core"
)

// Load parses the .http files at paths. A directory is searched
// recursively for *.http files in name order, skipping directories whose
// names start with a dot. The collection holds every file that parsed;
// the errors are for the rest.
func Load(paths ...string) (*core.Collection, []error) {
	c := &core.Collection{}
	var errs []error
	for _, path := range paths {
		files, err := Files(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, name := range files {
			f, err := ParseFile(name)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			c.Files = append(c.Files, f)
		}
	}
	return c, errs
}

// ParseFile reads and parses one .http file.
func ParseFile(path string) (*core.File, error) {
	src, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, src)
}

// ReadFile reads the .http file at path.
func ReadFile(path string) ([]byte, error) {
	src, err := os.ReadFile(path) //nolint:forbidigo,gosec // G304: a .http file named on the command line, or found below a directory named there
	if err != nil {
		return nil, core.Errorf(core.KindUsage, core.Source{}, "%v", err)
	}
	return src, nil
}

// Files returns the .http files at root, in the order Load parses them:
// root itself if it is a file.
func Files(root string) ([]string, error) {
	fi, err := os.Stat(root)
	if err != nil {
		return nil, core.Errorf(core.KindUsage, core.Source{}, "%v", err)
	}
	if !fi.IsDir() {
		return []string{root}, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && path != root && strings.HasPrefix(d.Name(), "."):
			return filepath.SkipDir
		case !d.IsDir() && filepath.Ext(path) == ".http":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, core.Errorf(core.KindUsage, core.Source{}, "%v", err)
	}
	if len(files) == 0 {
		return nil, core.Errorf(core.KindUsage, core.Source{}, "no .http files in %s", root)
	}
	return files, nil
}
