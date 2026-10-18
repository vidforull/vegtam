// Package core is the library shared by every vegtam front end: the
// collection model, the .http parser, environments, secret resolution,
// request execution, assertions and captures, policy, and the JSON output
// schema.
//
// The CLI and the TUI only call into this package; neither holds request
// logic of its own.
package core
