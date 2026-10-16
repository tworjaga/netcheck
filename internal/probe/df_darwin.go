//go:build darwin

package probe

import "syscall"

const ipDontFrag = 28 // IP_DONTFRAG

func setDF(fd int) error { return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, ipDontFrag, 1) }
