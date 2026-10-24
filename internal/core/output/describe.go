package output

// Describe is what vegtam describe prints: what a program needs to know
// to run vegtam, in one document. The commands and their flags come from
// the command line itself, so that the document cannot drift from it.
type Describe struct {
	Name      string            `json:"name"` // vegtam
	Version   string            `json:"version"`
	Mode      DescribeMode      `json:"mode"`
	Commands  []DescribeCommand `json:"commands"`
	Flags     []DescribeFlag    `json:"flags"` // those of every command
	ExitCodes []DescribeExit    `json:"exit_codes"`
	Errors    []DescribeError   `json:"errors"`
	// Policy is what vegtam policy prints; PolicyError, in its place, why
	// the policy cannot be read.
	Policy      *Policy         `json:"policy,omitempty"`
	PolicyError *Error          `json:"policy_error,omitempty"`
	Never       []string        `json:"never"`  // what vegtam never does, whoever asks
	Schema      string          `json:"schema"` // the command that prints the JSON Schema
	History     DescribeHistory `json:"history"`
}

// DescribeMode is whether a person is at a terminal, and why, and what
// such a run does with a request that needs a secret value.
type DescribeMode struct {
	Unattended bool   `json:"unattended"`
	Why        string `json:"why"`
	Secrets    string `json:"secrets"` // RunSecretsAll, RunSecretsNone or RunSecretsKeeper
}

// DescribeCommand is a command, its arguments and its flags.
type DescribeCommand struct {
	Name    string         `json:"name"`  // such as run, or import postman
	Usage   string         `json:"usage"` // such as vegtam run <file>[#<name>|#<N>] | <dir>
	Summary string         `json:"summary"`
	Flags   []DescribeFlag `json:"flags"`
}

// DescribeFlag is a flag of a command.
type DescribeFlag struct {
	Name      string `json:"name"`                // --env
	Shorthand string `json:"shorthand,omitempty"` // -e
	// Value is none for a flag that takes none, such as --dry-run;
	// required; or optional, given with =, as --confirm=<ref>.
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`    // of the value, such as string, time or size
	Default string `json:"default,omitempty"` // the value when not given, if there is one to say
	Usage   string `json:"usage"`
}

// DescribeExit is an exit code and what it means.
type DescribeExit struct {
	Code    int    `json:"code"`
	Meaning string `json:"meaning"`
}

// DescribeError is a kind of error, its exit code, and its causes.
type DescribeError struct {
	Kind     string `json:"kind"`
	ExitCode int    `json:"exit_code"`
	Meaning  string `json:"meaning"`
}

// DescribeHistory is where the history of runs is, or why there is none.
type DescribeHistory struct {
	On   bool   `json:"on"`
	Path string `json:"path,omitempty"` // the file, when on
	Why  string `json:"why,omitempty"`  // why it is off
}
