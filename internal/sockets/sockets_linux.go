package sockets

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procRoot is a test seam.
var procRoot = "/proc"

// owners maps socket inodes to the process holding them, by reading every
// process's file descriptors. Other users' processes can't be read without
// root; partial says some were skipped.
func owners() (map[string]Socket, bool) {
	out := map[string]Socket{}
	partial := false
	dirs, _ := os.ReadDir(procRoot)
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(procRoot, d.Name(), "fd"))
		if err != nil {
			partial = true
			continue
		}
		comm, _ := os.ReadFile(filepath.Join(procRoot, d.Name(), "comm"))
		name := strings.TrimSpace(string(comm))
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(procRoot, d.Name(), "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if _, ok := out[inode]; !ok {
				out[inode] = Socket{PID: pid, Process: name}
			}
		}
	}
	return out, partial
}

func list() (Snapshot, error) {
	var all []Socket
	var inodes []string
	found := false
	for _, f := range []struct{ file, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"}} {
		b, err := os.ReadFile(filepath.Join(procRoot, "net", f.file))
		if err != nil {
			continue
		}
		found = true
		ss, in, err := ParseProcNet(string(b), f.proto)
		if err != nil {
			return Snapshot{}, err
		}
		all = append(all, ss...)
		inodes = append(inodes, in...)
	}
	if !found {
		return Snapshot{}, os.ErrNotExist
	}
	own, partial := owners()
	missing := false
	for i := range all {
		if o, ok := own[inodes[i]]; ok {
			all[i].PID, all[i].Process = o.PID, o.Process
		} else if inodes[i] != "0" {
			missing = true
		}
	}
	return Snapshot{Sockets: all, Partial: partial && missing, Method: "procfs"}, nil
}
