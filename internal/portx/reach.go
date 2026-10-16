package portx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Rule is one expectation: host:port, and whether a connection from here
// should get through ("allow"), be stopped ("deny"), or just be tried ("").
type Rule struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Expect string `json:"expect,omitempty"`
	Line   int    `json:"line,omitempty"` // in the rules file
}

// String is "host:port".
func (r Rule) String() string { return net.JoinHostPort(r.Host, strconv.Itoa(r.Port)) }

// ParseRule reads "host:port [allow|deny]".
func ParseRule(s string) (Rule, error) {
	f := strings.Fields(s)
	if len(f) == 0 || len(f) > 2 {
		return Rule{}, fmt.Errorf("%q: expected host:port and optionally allow or deny", s)
	}
	h, p, err := net.SplitHostPort(f[0])
	if err != nil {
		return Rule{}, fmt.Errorf("%q: give the port too, like example.com:443", f[0])
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return Rule{}, fmt.Errorf("%q isn't a port", p)
	}
	r := Rule{Host: h, Port: port}
	if len(f) == 2 {
		switch e := strings.ToLower(f[1]); e {
		case "allow", "allowed", "open", "pass":
			r.Expect = "allow"
		case "deny", "denied", "block", "blocked", "closed", "drop":
			r.Expect = "deny"
		default:
			return Rule{}, fmt.Errorf("%q: the expectation is allow or deny", f[1])
		}
	}
	return r, nil
}

// Outcome of one connection attempt.
const (
	Open     = "open"     // the connection was accepted
	Refused  = "refused"  // something answered "no" (the host, or a firewall rejecting)
	Filtered = "filtered" // no answer at all: dropped on the way
	Failed   = "failed"   // couldn't try: the name doesn't resolve, no route
)

// ReachResult is one rule tried.
type ReachResult struct {
	Rule
	Addr   string        `json:"addr,omitempty"`
	Result string        `json:"result"`
	RTT    time.Duration `json:"rtt_ns,omitempty"`
	Holds  *bool         `json:"holds,omitempty"` // nil without an expectation
	Error  string        `json:"error,omitempty"`
}

// dialReach is a test seam.
var dialReach = func(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	took := time.Since(start)
	c.Close()
	return took, nil
}

func classify(err error) (string, string) {
	var dns *net.DNSError
	var ne net.Error
	switch {
	case err == nil:
		return Open, ""
	case errors.As(err, &dns):
		return Failed, "the name doesn't resolve"
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "refused"):
		return Refused, ""
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return Filtered, ""
	case strings.Contains(err.Error(), "unreachable"):
		return Failed, "no route to it"
	}
	return Failed, err.Error()
}

// Reach tries every rule: up to 20 at once, each attempt paced by wait
// (nil: no pacing).
func Reach(ctx context.Context, rules []Rule, timeout time.Duration, wait func(context.Context) error) []ReachResult {
	out := make([]ReachResult, len(rules))
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	for i, r := range rules {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := ReachResult{Rule: r}
			if wait != nil {
				if err := wait(ctx); err != nil {
					res.Result, res.Error = Failed, "interrupted"
					out[i] = res
					return
				}
			}
			res.Addr = r.String()
			rtt, err := dialReach(ctx, r.String(), timeout)
			res.RTT = rtt
			res.Result, res.Error = classify(err)
			if r.Expect != "" && res.Result != Failed {
				holds := (res.Result == Open) == (r.Expect == "allow")
				res.Holds = &holds
			}
			out[i] = res
		}()
	}
	wg.Wait()
	return out
}
