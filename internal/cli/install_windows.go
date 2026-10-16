//go:build windows

package cli

import (
	"syscall"
	"unsafe"
)

// The user's own PATH lives in the registry under HKCU\Environment; changing
// it needs no administrator rights. Windows only re-reads it in programs
// started after a WM_SETTINGCHANGE broadcast, hence "open a new terminal".

var (
	advapi32                = syscall.NewLazyDLL("advapi32.dll")
	procRegSetValueExW      = advapi32.NewProc("RegSetValueExW")
	user32                  = syscall.NewLazyDLL("user32.dll")
	procSendMessageTimeoutW = user32.NewProc("SendMessageTimeoutW")
)

const (
	keySetValue      = 0x0002
	hwndBroadcast    = 0xffff
	wmSettingChange  = 0x001A
	smtoAbortIfHung  = 0x0002
	broadcastTimeout = 5000 // ms
)

func utf16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

// userPath reads the user's PATH from the registry ("" when it has none).
var userPath = func() (string, error) {
	var k syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, utf16("Environment"), 0, syscall.KEY_READ, &k); err != nil {
		return "", err
	}
	defer syscall.RegCloseKey(k)
	var typ, n uint32
	err := syscall.RegQueryValueEx(k, utf16("Path"), nil, &typ, nil, &n)
	if err == syscall.ERROR_FILE_NOT_FOUND {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	buf := make([]uint16, n/2+1)
	if err := syscall.RegQueryValueEx(k, utf16("Path"), nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n); err != nil {
		return "", err
	}
	return syscall.UTF16ToString(buf), nil
}

// setUserPath writes the user's PATH (as REG_EXPAND_SZ, like Windows does)
// and tells running programs that the environment changed.
var setUserPath = func(v string) error {
	var k syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, utf16("Environment"), 0, keySetValue, &k); err != nil {
		return err
	}
	defer syscall.RegCloseKey(k)
	data, err := syscall.UTF16FromString(v)
	if err != nil {
		return err
	}
	if r, _, _ := procRegSetValueExW.Call(uintptr(k), uintptr(unsafe.Pointer(utf16("Path"))), 0, syscall.REG_EXPAND_SZ,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2)); r != 0 {
		return syscall.Errno(r)
	}
	var res uintptr
	procSendMessageTimeoutW.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(utf16("Environment"))),
		smtoAbortIfHung, broadcastTimeout, uintptr(unsafe.Pointer(&res)))
	return nil
}
