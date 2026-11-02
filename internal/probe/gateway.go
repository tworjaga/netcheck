// Package probe holds the network measurements behind each netcheck command.
// Everything here uses only the Go standard library and needs no elevated
// privileges.
package probe

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// DefaultGateway returns the IPv4 address of the default route's next hop.
func DefaultGateway() (net.IP, error) {
	switch runtime.GOOS {
	case "linux":
		return gatewayLinux()
	case "darwin":
		return gatewayDarwin()
	case "windows":
		return gatewayWindows()
	}
	return nil, errors.New("unsupported OS")
}

func gatewayLinux() (net.IP, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	for _, ln := range lines[min(1, len(lines)):] {
		f := strings.Fields(ln)
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		flags, _ := strconv.ParseUint(f[3], 16, 32)
		if flags&0x2 == 0 { // RTF_GATEWAY
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil {
			continue
		}
		return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)), nil
	}
	return nil, errors.New("no default route")
}

func gatewayDarwin() (net.IP, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return nil, err
	}
	for _, ln := range strings.Split(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) == 2 && f[0] == "gateway:" {
			if ip := net.ParseIP(f[1]); ip != nil {
				return ip, nil
			}
		}
	}
	return nil, errors.New("no default route")
}

func gatewayWindows() (net.IP, error) {
	out, err := exec.Command("route", "print", "-4", "0.0.0.0").Output()
	if err != nil {
		return nil, err
	}
	for _, ln := range strings.Split(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" {
			if ip := net.ParseIP(f[2]); ip != nil {
				return ip, nil
			}
		}
	}
	return nil, errors.New("no default route")
}

// LocalIP returns the address this machine would use to reach the internet.
// Dialing UDP sends no packets; it only selects a route.
func LocalIP() net.IP {
	c, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return nil
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP
	}
	return nil
}
