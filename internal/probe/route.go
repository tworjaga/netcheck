package probe

import (
	"context"
	"errors"
	"math"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hop is one router on the way to a destination, with running statistics.
type Hop struct {
	TTL       int       `json:"ttl"`
	IP        string    `json:"ip,omitempty"` // empty: this hop never answered
	Sent      int       `json:"sent"`
	Received  int       `json:"received"`
	LossPct   float64   `json:"loss_pct"`
	LastMs    float64   `json:"last_ms"`
	AvgMs     float64   `json:"avg_ms"`
	BestMs    float64   `json:"best_ms"`
	WorstMs   float64   `json:"worst_ms"`
	SamplesMs []float64 `json:"samples_ms"` // -1 = lost
}

func (h *Hop) record(ms float64) {
	h.Sent++
	h.SamplesMs = append(h.SamplesMs, ms)
	if ms >= 0 {
		h.Received++
		h.LastMs = ms
		if h.Received == 1 || ms < h.BestMs {
			h.BestMs = ms
		}
		h.WorstMs = math.Max(h.WorstMs, ms)
		h.AvgMs += (ms - h.AvgMs) / float64(h.Received)
	}
	h.LossPct = float64(h.Sent-h.Received) / float64(h.Sent) * 100
}

// RouteResult is a traced path. Method is "icmp" (TTL probing),
// "icmp+system" (hops found by the system tool, then pinged) or "system".
type RouteResult struct {
	Target  string `json:"target"`
	Addr    string `json:"addr,omitempty"`
	Method  string `json:"method"`
	Reached bool   `json:"reached"`
	Hops    []Hop  `json:"hops"`
	Note    string `json:"note,omitempty"`
	Error   string `json:"error,omitempty"`
}

// RouteOpts tunes a trace.
type RouteOpts struct {
	MaxHops  int           // default 30
	Rounds   int           // probes per hop; 0 = until ctx ends; 1 = discovery pass only
	Interval time.Duration // between rounds
	OnUpdate func(RouteResult)
}

func snapshot(r RouteResult) RouteResult {
	r.Hops = append([]Hop(nil), r.Hops...)
	return r
}

// discoverTTL walks TTL 1,2,3... until the destination answers. It stops
// early after four silent hops in a row (a filtered destination).
func discoverTTL(ctx context.Context, e Echoer, dst net.IP, maxHops int, onHop func([]Hop)) ([]Hop, bool) {
	var hops []Hop
	silent := 0
	for ttl := 1; ttl <= maxHops && ctx.Err() == nil; ttl++ {
		var r EchoReply
		for try := 0; try < 2 && ctx.Err() == nil; try++ {
			r, _ = e.Echo(dst, EchoOpts{TTL: ttl, Timeout: 800 * time.Millisecond})
			if r.Kind != EchoTimeout {
				break
			}
		}
		h := Hop{TTL: ttl}
		ms := -1.0
		switch r.Kind {
		case EchoOK, EchoTTLExceeded, EchoUnreachable:
			if r.From != nil {
				h.IP = r.From.String()
			}
			if r.Kind != EchoUnreachable {
				ms = float64(r.RTT.Microseconds()) / 1000
			}
			silent = 0
		default:
			silent++
		}
		h.record(ms)
		hops = append(hops, h)
		if onHop != nil {
			onHop(hops)
		}
		if r.Kind == EchoOK {
			return hops, true
		}
		if r.Kind == EchoUnreachable || silent >= 4 {
			break
		}
	}
	for len(hops) > 0 && hops[len(hops)-1].IP == "" { // trim trailing silence
		hops = hops[:len(hops)-1]
	}
	return hops, false
}

// roundOnce probes every hop once, in parallel.
func roundOnce(hops []Hop, probe func(h *Hop) (float64, bool)) {
	var wg sync.WaitGroup
	res := make([]float64, len(hops))
	skip := make([]bool, len(hops))
	for i := range hops {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ms, ok := probe(&hops[i])
			res[i], skip[i] = ms, !ok
		}(i)
	}
	wg.Wait()
	for i := range hops {
		if !skip[i] {
			hops[i].record(res[i])
		}
	}
}

// Trace finds the path to host and keeps measuring every hop, like mtr.
// It prefers ICMP with rising TTLs, and falls back to the system's tracert
// or traceroute (then pings the hops it found) where TTL replies can't be
// read, which includes unprivileged Linux ping sockets.
func Trace(ctx context.Context, host string, o RouteOpts) RouteResult {
	if o.MaxHops <= 0 {
		o.MaxHops = 30
	}
	if o.Interval <= 0 {
		o.Interval = 500 * time.Millisecond
	}
	res := RouteResult{Target: host}
	ipStr, err := resolve(ctx, host)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Addr = ipStr
	dst := net.ParseIP(ipStr)
	if dst.To4() == nil {
		res.Error = "route tracing supports IPv4 destinations only"
		return res
	}
	notify := func() {
		if o.OnUpdate != nil {
			o.OnUpdate(snapshot(res))
		}
	}

	var probeHop func(h *Hop) (float64, bool)
	e, eerr := openEchoer()
	if eerr == nil {
		res.Method = "icmp"
		res.Hops, res.Reached = discoverTTL(ctx, e, dst, o.MaxHops, func(h []Hop) { res.Hops = h; notify() })
		// Answering hops are probed one at a time: on a real Windows Wi-Fi
		// link, a burst of simultaneous TTL probes came back with every hop
		// ~10 ms slower, hiding where latency really rises. Silent hops stay
		// parallel so their timeouts don't add up.
		var ttlMu sync.Mutex
		probeHop = func(h *Hop) (float64, bool) {
			if h.IP != "" {
				ttlMu.Lock()
				defer ttlMu.Unlock()
			}
			r, _ := e.Echo(dst, EchoOpts{TTL: h.TTL, Timeout: icmpTimeout})
			if r.Kind == EchoOK || r.Kind == EchoTTLExceeded {
				return float64(r.RTT.Microseconds()) / 1000, true
			}
			return -1, true
		}
	}
	answered := false
	for _, h := range res.Hops {
		if h.IP != "" {
			answered = true
		}
	}
	if ctx.Err() != nil {
		res.Error = "interrupted"
		return res
	}
	if !answered {
		hops, reached, serr := systemTrace(ctx, dst, o.MaxHops)
		if serr != nil {
			if eerr != nil {
				res.Error = "no tracing method works here (" + serr.Error() + ")"
			} else {
				res.Note = "no router answered, so the route is unknown (ICMP may be filtered)"
			}
			return res
		}
		res.Hops, res.Reached, res.Method = hops, reached, "system"
		if eerr == nil {
			res.Method = "icmp+system"
			res.Note = "hops found with the system trace tool, then pinged directly; some routers ignore ping"
			probeHop = func(h *Hop) (float64, bool) {
				if h.IP == "" {
					return 0, false
				}
				r, _ := e.Echo(net.ParseIP(h.IP), EchoOpts{Timeout: icmpTimeout})
				if r.Kind == EchoOK {
					return float64(r.RTT.Microseconds()) / 1000, true
				}
				return -1, true
			}
		} else {
			res.Note = "single pass with the system trace tool; live loss needs ICMP"
		}
	}
	notify()
	if probeHop == nil {
		return res
	}
	for round := 1; (o.Rounds == 0 || round < o.Rounds) && ctx.Err() == nil; round++ {
		sleep(ctx, o.Interval)
		if ctx.Err() != nil {
			break
		}
		roundOnce(res.Hops, probeHop)
		notify()
	}
	return res
}

// FirstHops returns the addresses of the first n routers toward dst (nil
// entries for silent hops). It's used for NAT detection.
func FirstHops(ctx context.Context, dst string, n int) []net.IP {
	r := Trace(ctx, dst, RouteOpts{MaxHops: n, Rounds: 1})
	var out []net.IP
	for _, h := range r.Hops {
		out = append(out, net.ParseIP(h.IP))
	}
	return out
}

// ---- system tool fallback ----

var reHopLine = regexp.MustCompile(`^\s*(\d{1,3})\s+(.*)$`)

func parseHopLines(out string) []Hop {
	var hops []Hop
	for _, ln := range strings.Split(out, "\n") {
		m := reHopLine.FindStringSubmatch(strings.TrimRight(ln, "\r"))
		if m == nil {
			continue
		}
		ttl, _ := strconv.Atoi(m[1])
		h := Hop{TTL: ttl}
		toks := strings.Fields(strings.NewReplacer("[", " ", "]", " ").Replace(m[2]))
		ms := -1.0
		for i, t := range toks {
			if ip := net.ParseIP(t); ip != nil {
				h.IP = ip.String()
			}
			if t == "ms" && i > 0 && ms < 0 {
				ms = parseMs(toks[i-1])
			} else if strings.HasSuffix(t, "ms") && len(t) > 2 && ms < 0 {
				ms = parseMs(strings.TrimSuffix(t, "ms"))
			}
		}
		if h.IP == "" {
			ms = -1
		}
		h.record(ms)
		hops = append(hops, h)
	}
	return hops
}

func parseMs(s string) float64 {
	if strings.HasPrefix(s, "<") { // Windows prints "<1 ms"
		return 0.5
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return -1
	}
	return v
}

// systemTrace runs tracert (Windows) or traceroute (Unix) once.
func systemTrace(ctx context.Context, dst net.IP, maxHops int) ([]Hop, bool, error) {
	var out string
	var err error
	hopsArg := strconv.Itoa(maxHops)
	if runtime.GOOS == "windows" {
		out, err = Run(ctx, 45*time.Second, "tracert", "-d", "-h", hopsArg, "-w", "700", dst.String())
	} else {
		out, err = Run(ctx, 45*time.Second, "traceroute", "-n", "-m", hopsArg, "-w", "1", "-q", "1", dst.String())
	}
	hops := parseHopLines(out)
	if len(hops) == 0 {
		if err == nil {
			err = errors.New("no output")
		}
		return nil, false, err
	}
	for len(hops) > 0 && hops[len(hops)-1].IP == "" {
		hops = hops[:len(hops)-1]
	}
	reached := len(hops) > 0 && hops[len(hops)-1].IP == dst.String()
	return hops, reached, nil
}
