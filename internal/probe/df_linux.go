//go:build linux

package probe

import "syscall"

// setDF forbids fragmentation (IP_MTU_DISCOVER = IP_PMTUDISC_DO).
func setDF(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)
}
