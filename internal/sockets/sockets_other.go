//go:build !windows && !linux

package sockets

import (
	"fmt"
	"os"
	"os/exec"
)

// macOS and the BSDs: lsof knows the owners. Without root it sees only
// this user's processes' sockets.
func list() (Snapshot, error) {
	out, err := exec.Command("lsof", "-nP", "-iTCP", "-iUDP", "-F", "pcPnT").Output()
	if err != nil && len(out) == 0 {
		return Snapshot{}, fmt.Errorf("lsof failed: %v", err)
	}
	return Snapshot{Sockets: ParseLsof(string(out)), Partial: os.Geteuid() != 0, Method: "lsof"}, nil
}
