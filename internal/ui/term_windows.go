//go:build windows

package ui

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode     = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode     = kernel32.NewProc("SetConsoleMode")
	procReadConsoleInputW  = kernel32.NewProc("ReadConsoleInputW")
	procWaitForSingleObj   = kernel32.NewProc("WaitForSingleObject")
	procFlushConsoleBuffer = kernel32.NewProc("FlushConsoleInputBuffer")
)

const (
	enableProcessedInput  = 0x0001
	enableLineInput       = 0x0002
	enableEchoInput       = 0x0004
	enableVTProcessing    = 0x0004 // output mode: ENABLE_VIRTUAL_TERMINAL_PROCESSING
	keyEventType          = 0x0001
	waitTimeoutResult     = 0x00000102
	keyPollIntervalMillis = 100
)

func getMode(h syscall.Handle) (uint32, bool) {
	var m uint32
	r, _, _ := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&m)))
	return m, r != 0
}

// enableVT turns on ANSI escape processing so colors and spinners render in
// cmd.exe, PowerShell and Windows Terminal.
func enableVT() {
	h, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		return
	}
	if mode, ok := getMode(h); ok {
		procSetConsoleMode.Call(uintptr(h), uintptr(mode|enableVTProcessing))
	}
}

// isTerminal is true only for a real console. (A plain ModeCharDevice check
// would also accept NUL.)
func isTerminal(f *os.File) bool {
	_, ok := getMode(syscall.Handle(f.Fd()))
	return ok
}

// rawOn switches console input to single-key mode: no line buffering, no
// echo, Ctrl-C delivered as a key so the menu can handle it. The returned
// function restores the previous mode. It fails when stdin isn't a real
// console (a pipe, some MSYS terminals); the menu then falls back to a
// numbered prompt.
func rawOn() (func(), error) {
	h := syscall.Handle(os.Stdin.Fd())
	saved, ok := getMode(h)
	if !ok {
		return nil, errors.New("stdin is not a console")
	}
	raw := saved &^ (enableLineInput | enableEchoInput | enableProcessedInput)
	if r, _, _ := procSetConsoleMode.Call(uintptr(h), uintptr(raw)); r == 0 {
		return nil, errors.New("SetConsoleMode failed")
	}
	procFlushConsoleBuffer.Call(uintptr(h))
	return func() { procSetConsoleMode.Call(uintptr(h), uintptr(saved)) }, nil
}

// inputRecord mirrors INPUT_RECORD for KEY_EVENT (20 bytes).
type inputRecord struct {
	EventType uint16
	_         uint16
	KeyDown   int32
	Repeat    uint16
	VKey      uint16
	Scan      uint16
	Char      uint16
	Ctrl      uint32
}

// readKey waits up to ~100 ms for a key press, using the console's own key
// events, so a bare Esc is unambiguous and mouse/focus/resize events can't
// block the read.
func readKey() KeyEvent {
	h := syscall.Handle(os.Stdin.Fd())
	r, _, _ := procWaitForSingleObj.Call(uintptr(h), uintptr(keyPollIntervalMillis))
	if r == waitTimeoutResult {
		return KeyEvent{}
	}
	var rec inputRecord
	var n uint32
	ok, _, _ := procReadConsoleInputW.Call(uintptr(h), uintptr(unsafe.Pointer(&rec)), 1, uintptr(unsafe.Pointer(&n)))
	if ok == 0 || n == 0 || rec.EventType != keyEventType || rec.KeyDown == 0 {
		return KeyEvent{}
	}
	return translateKey(rec.VKey, rec.Char, rec.Ctrl)
}

var procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")

// termSize is the visible size of the console window, 0 if unknown.
func termSize() (int, int) {
	h, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		return 0, 0
	}
	// CONSOLE_SCREEN_BUFFER_INFO: size, cursor, attributes, then the window
	// rectangle (left, top, right, bottom) and the maximum size.
	var info struct {
		size, cursor             [2]int16
		attr                     uint16
		left, top, right, bottom int16
		max                      [2]int16
	}
	if r, _, _ := procGetConsoleScreenBufferInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&info))); r == 0 {
		return 0, 0
	}
	return int(info.right-info.left) + 1, int(info.bottom-info.top) + 1
}
