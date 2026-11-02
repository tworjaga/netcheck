package cli

import "syscall"

// detachConsole lets go of the console window a sign-in task opens, so
// the agent runs out of sight (its output goes to the log).
func detachConsole() {
	syscall.NewLazyDLL("kernel32.dll").NewProc("FreeConsole").Call()
}
