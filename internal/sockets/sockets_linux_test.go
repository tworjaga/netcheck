package sockets

import (
	"os"
	"path/filepath"
	"testing"
)

// A fake /proc: one listening socket owned by "sshd" (pid 42), one
// connection whose owner can't be read.
func TestListProcfs(t *testing.T) {
	root := t.TempDir()
	write := func(p, s string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		if err := os.WriteFile(filepath.Join(root, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("net/tcp", "  sl  local_address rem_address   st\n"+
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1\n"+
		"   1: 0200000A:C350 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 222 1\n")
	write("42/comm", "sshd\n")
	os.MkdirAll(filepath.Join(root, "42", "fd"), 0o755)
	if err := os.Symlink("socket:[111]", filepath.Join(root, "42", "fd", "3")); err != nil {
		t.Skip("no symlinks here")
	}
	os.MkdirAll(filepath.Join(root, "43"), 0o755) // no fd dir: another user's process
	old := procRoot
	procRoot = root
	defer func() { procRoot = old }()

	snap, err := list()
	if err != nil || len(snap.Sockets) != 2 || snap.Method != "procfs" {
		t.Fatalf("%+v %v", snap, err)
	}
	if s := snap.Sockets[0]; s.Process != "sshd" || s.PID != 42 || s.LocalPort != 22 {
		t.Errorf("owner: %+v", s)
	}
	if !snap.Partial || snap.Sockets[1].Process != "" {
		t.Errorf("the second socket's owner can't be seen: %+v", snap)
	}
}
