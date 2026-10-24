package output

// Store is the person's store of secrets as vegtam secret prints it: the
// name of each secret and the origins it may go to, never a value.
type Store struct {
	Path    string        `json:"path"`
	Exists  bool          `json:"exists"`
	Secrets []StoreSecret `json:"secrets"`
	// Imported are the names that vegtam secret import put in the store,
	// and From the file and the environment they came from.
	Imported []string  `json:"imported,omitempty"`
	From     string    `json:"from,omitempty"`
	Warnings []Warning `json:"warnings,omitempty"`
}

// StoreSecret is a secret of the store, by name, with the origins it may
// go to: none for one bound to none, which goes nowhere.
type StoreSecret struct {
	Name    string   `json:"name"`
	Allowed []string `json:"allowed"`
}
