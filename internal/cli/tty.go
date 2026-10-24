package cli

import (
	"errors"
	"io"
	"os"

	"github.com/charmbracelet/x/term"
)

// terminal is where a person types what vegtam never takes from a flag,
// a variable or a file: the password of the store of secrets, and the
// value of a secret.
type terminal interface {
	// ReadSecret writes prompt and reads a line without echo.
	ReadSecret(prompt string) ([]byte, error)
}

// errNoTerminal is the error of a terminal that is not there.
var errNoTerminal = errors.New("no terminal to type it at: the password of the store, and the value of a secret, are typed, never passed")

// tty is the controlling terminal of the process, /dev/tty: whatever stdin
// and stdout are, a person types there, and nothing that runs vegtam with
// a pipe can answer for them.
type tty struct{}

func (tty) ReadSecret(prompt string) (b []byte, err error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0) //nolint:forbidigo // the controlling terminal, for a password: no path from a file
	if err != nil {
		return nil, errNoTerminal
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	if !term.IsTerminal(f.Fd()) {
		return nil, errNoTerminal
	}
	if _, err = io.WriteString(f, prompt); err != nil {
		return nil, err
	}
	b, err = term.ReadPassword(f.Fd())
	if _, werr := io.WriteString(f, "\n"); err == nil {
		err = werr
	}
	return b, err
}

// readSecret reads a line without echo at the terminal of c, after
// prompt.
func (c *Config) readSecret(prompt string) ([]byte, error) {
	if c.term != nil {
		return c.term.ReadSecret(prompt)
	}
	return tty{}.ReadSecret(prompt)
}
