//go:build !windows

package cli

import "os"

// On macOS and Linux PATH is set by shell profiles, which netcheck doesn't
// edit: install shows the line to add instead.

var userPath = func() (string, error) { return os.Getenv("PATH"), nil }

// setUserPath is nil: there's no per-user PATH store to write to.
var setUserPath func(string) error
