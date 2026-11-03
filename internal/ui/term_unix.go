//go:build !windows

package ui

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

func enableVT() {}

// isTerminal asks the terminal driver for its size, which only a real
// terminal answers (like isatty). A character-device check would also
// accept /dev/null, which is stdin on CI runners and under cron.
func isTerminal(f *os.File) bool {
	var ws struct{ row, col, x, y uint16 }
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	return e == 0
}

// rawOn puts the terminal into single-key mode (no line buffering, no echo)
// and returns a function that restores the previous state. Reads time out
// after 100 ms so a bare Esc can be told apart from an arrow-key sequence.
func rawOn() (func(), error) {
	get := exec.Command("stty", "-g")
	get.Stdin = os.Stdin
	out, err := get.Output()
	if err != nil {
		return nil, err
	}
	saved := strings.TrimSpace(string(out))
	if saved == "" {
		return nil, errors.New("stty returned no state")
	}
	set := exec.Command("stty", "-icanon", "-echo", "-isig", "min", "0", "time", "1")
	set.Stdin = os.Stdin
	if err := set.Run(); err != nil {
		return nil, err
	}
	return func() {
		r := exec.Command("stty", saved)
		r.Stdin = os.Stdin
		_ = r.Run()
	}, nil
}

func readByte() (byte, bool) {
	var b [1]byte
	n, _ := os.Stdin.Read(b[:])
	if n == 1 {
		return b[0], true
	}
	return 0, false // VTIME timeout surfaces as a zero-length read
}

// readKey waits up to ~100 ms for a key press.
func readKey() KeyEvent { return parseKey(readByte) }

// termSize is the terminal's size from TIOCGWINSZ, 0 if unknown.
func termSize() (int, int) {
	var ws struct{ row, col, x, y uint16 }
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, os.Stdout.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if e != 0 {
		return 0, 0
	}
	return int(ws.col), int(ws.row)
}
