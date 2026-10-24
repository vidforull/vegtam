package output

// Doctor is what vegtam doctor prints: whether a person is at a terminal,
// what the operator's policy says of secrets, where the secrets of the
// current directory are and who besides the person can read them, and
// whether the keeper is there. It holds names, paths and permission bits,
// never a secret value: doctor reads none.
type Doctor struct {
	Mode    DescribeMode  `json:"mode"`
	Policy  DoctorPolicy  `json:"policy"`
	Secrets DoctorSecrets `json:"secrets"`
	Keeper  DoctorKeeper  `json:"keeper"`
	// Multiplexers are the terminal multiplexers that the shell runs in, as
	// their variables say; none outside one.
	Multiplexers []DoctorMultiplexer `json:"multiplexers,omitempty"`
	Config       DoctorConfig        `json:"config"`
	Warnings     []Warning           `json:"warnings,omitempty"` // what the rest gives cause to look at, in its order
}

// DoctorPolicy is what the operator's policy says of secrets, or why it
// cannot be read.
type DoctorPolicy struct {
	Path  string `json:"path,omitempty"` // the file, found or not; absent if there is no place for it
	Found bool   `json:"found"`          // a file is there
	// Error is why the file cannot be read, as every command that reads it
	// would fail; the fields after it are then absent.
	Error *Error `json:"error,omitempty"`
	// SecretsMode is what a run without a person does with secrets, as it
	// applies: the file's values, or the defaults.
	SecretsMode *PolicySecretsMode `json:"secrets_mode,omitempty"`
	Env         []string           `json:"env,omitempty"` // the NAME of each {{$env NAME}} it binds
	Cmd         []string           `json:"cmd,omitempty"` // the NAME of each {{$cmd NAME}} it binds
}

// DoctorSecrets is where the secrets of the current directory are, as a
// run of a .http file in it finds them, without their values.
type DoctorSecrets struct {
	Dir string `json:"dir,omitempty"` // the current directory; absent if it cannot be told
	// PrivateFile is the nearest http-client.private.env.json from Dir
	// upwards; nil if there is none.
	PrivateFile *DoctorPath `json:"private_file,omitempty"`
	// Environment are the variables that the policy names, by its
	// {{$env NAME}} and its network.proxy_auth, that the process
	// environment holds a value for.
	Environment []string `json:"environment,omitempty"`
}

// DoctorKeeper is where the keeper listens, whether it answers there, and
// what it says of itself.
type DoctorKeeper struct {
	Socket DoctorPath `json:"socket"`
	// Running is true when a keeper of this user answered on Socket, in
	// the protocol of this vegtam.
	Running bool   `json:"running"`
	Why     string `json:"why,omitempty"` // why Running is false
	PID     int    `json:"pid,omitempty"` // the keeper's
	// Multiplexer is the terminal multiplexer the keeper runs in, as it
	// says: another process can read and type into its terminal.
	Multiplexer string `json:"multiplexer,omitempty"`
}

// DoctorMultiplexer is a terminal multiplexer that the shell runs in.
type DoctorMultiplexer struct {
	Name     string `json:"name"`     // tmux or screen
	Variable string `json:"variable"` // the one that says so: TMUX or STY
}

// DoctorConfig is vegtam's configuration directory and the policy file in
// it, as the file system has them.
type DoctorConfig struct {
	Dir    DoctorPath `json:"dir"`
	Policy DoctorPath `json:"policy"`
}

// DoctorPath is what is at a path: nothing, or a file, a directory or a
// socket, with its permission bits and its owner; never what is in it.
type DoctorPath struct {
	Path   string `json:"path,omitempty"` // absent if there is no place for it, which Why says
	Exists bool   `json:"exists"`
	Type   string `json:"type,omitempty"` // PathFile, PathDir, PathSocket or PathOther; absent if nothing is there
	Mode   string `json:"mode,omitempty"` // the permission bits in octal, such as 0600
	UID    *int   `json:"uid,omitempty"`  // the owner; absent where the system does not say
	Owned  bool   `json:"owned"`          // it belongs to the user vegtam runs as
	Why    string `json:"why,omitempty"`  // why there is no path, or what is there cannot be looked at
}

// The types of what is at a DoctorPath.
const (
	PathFile   = "file"
	PathDir    = "directory"
	PathSocket = "socket"
	PathOther  = "other" // a named pipe or a device
)
