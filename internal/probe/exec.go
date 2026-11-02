package probe

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// Run executes an external command with a hard timeout and returns its
// standard output. It is a variable so tests can substitute canned output.
var Run = func(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil && out.Len() == 0 && errb.Len() > 0 {
		return errb.String(), err
	}
	return out.String(), err
}
