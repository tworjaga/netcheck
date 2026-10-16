//go:build windows

package probe

import (
	"context"
	"net"
	"strings"
	"syscall"
)

// dnsQueryBypassCache is DNS_QUERY_BYPASS_CACHE from windns.h.
const dnsQueryBypassCache = 0x8

// dnsRcodeNameError is DNS_ERROR_RCODE_NAME_ERROR: the name doesn't exist.
const dnsRcodeNameError = 9003

func init() { systemLookup = lookupBypassingCache }

// lookupBypassingCache asks Windows' configured DNS servers, as the system
// resolver would, but skips the local DNS cache. Through the cache a name
// looked up a minute ago answers in half a millisecond, which made the
// system resolver look far faster than it is.
func lookupBypassingCache(ctx context.Context, name string) (bool, error) {
	type answer struct {
		found bool
		err   error
	}
	ch := make(chan answer, 1)
	go func() {
		var rec *syscall.DNSRecord
		err := syscall.DnsQuery(strings.TrimSuffix(name, "."), syscall.DNS_TYPE_A, dnsQueryBypassCache, nil, &rec, nil)
		found := false
		if err == nil {
			for r := rec; r != nil; r = r.Next {
				if r.Type == syscall.DNS_TYPE_A {
					found = true
				}
			}
			syscall.DnsRecordListFree(rec, 1)
		}
		if en, ok := err.(syscall.Errno); ok && en == dnsRcodeNameError {
			err = &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
		ch <- answer{found, err}
	}()
	select {
	case a := <-ch:
		return a.found, a.err
	case <-ctx.Done():
		return false, &net.DNSError{Err: "timed out", Name: name, IsTimeout: true}
	}
}
