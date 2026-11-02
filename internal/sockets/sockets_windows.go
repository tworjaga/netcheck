package sockets

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	afInet                = 2
	afInet6               = 23
	tcpTableOwnerPIDAll   = 5
	udpTableOwnerPID      = 1
	errInsufficientBuffer = 122
)

// table calls GetExtendedTcpTable or GetExtendedUdpTable, growing the
// buffer until the table fits.
func table(proc *syscall.LazyProc, af, class uintptr) ([]byte, error) {
	size := uint32(16 << 10)
	for tries := 0; tries < 5; tries++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, af, class, 0)
		switch r {
		case 0:
			return buf[:size], nil
		case errInsufficientBuffer:
			size += 4 << 10 // sockets come and go between calls
			continue
		default:
			return nil, fmt.Errorf("%s failed: %v", proc.Name, syscall.Errno(r))
		}
	}
	return nil, fmt.Errorf("%s: the table kept growing", proc.Name)
}

// processNames maps every PID to its program name, from a process
// snapshot (which needs no admin rights).
func processNames() map[int]string {
	names := map[int]string{0: "System Idle Process", 4: "System"}
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return names
	}
	defer syscall.CloseHandle(snap)
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err := syscall.Process32First(snap, &e); err == nil; err = syscall.Process32Next(snap, &e) {
		names[int(e.ProcessID)] = syscall.UTF16ToString(e.ExeFile[:])
	}
	return names
}

func list() (Snapshot, error) {
	if err := iphlpapi.Load(); err != nil {
		return Snapshot{}, err
	}
	var all []Socket
	for _, t := range []struct {
		proc  *syscall.LazyProc
		af    uintptr
		class uintptr
		parse func([]byte, bool) []Socket
		v6    bool
	}{
		{procGetExtendedTcpTable, afInet, tcpTableOwnerPIDAll, ParseTCPTable, false},
		{procGetExtendedTcpTable, afInet6, tcpTableOwnerPIDAll, ParseTCPTable, true},
		{procGetExtendedUdpTable, afInet, udpTableOwnerPID, ParseUDPTable, false},
		{procGetExtendedUdpTable, afInet6, udpTableOwnerPID, ParseUDPTable, true},
	} {
		b, err := table(t.proc, t.af, t.class)
		if err != nil {
			if t.v6 {
				continue // no IPv6 stack: fine
			}
			return Snapshot{}, err
		}
		all = append(all, t.parse(b, t.v6)...)
	}
	names := processNames()
	for i := range all {
		all[i].Process = names[all[i].PID]
	}
	return Snapshot{Sockets: all, Method: "iphlpapi"}, nil
}
