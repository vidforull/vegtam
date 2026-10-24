package policy

import (
	"crypto/rand"
	"os"
	"runtime"
)

// WriteFile writes data to the file name in root, readable by its owner
// only: to a new file beside it, synced and closed, then renamed over
// name, and the directory synced, so that a reader finds the old file or
// the new one whole, after a crash too. The mode of an old file does not
// carry over.
func WriteFile(root *os.Root, name string, data []byte) error {
	tmp := "." + name + "." + rand.Text() + ".tmp"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:forbidigo // the files of vegtam's configuration directory: Sync, Close and Rename are checked
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
		return err
	}
	return syncDir(root)
}

// syncDir syncs the directory root, which makes a rename in it last.
func syncDir(root *os.Root) error {
	if runtime.GOOS == "windows" { // where a directory cannot be synced
		return nil
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
