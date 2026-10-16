// Package uptime watches a list of servers: HTTP(S) pages, TCP ports, ping
// and DNS names. It turns checks into up/down events, keeps a history and
// sums it up as uptime and outages.
package uptime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
)

// Kinds of check.
const (
	HTTP = "http" // http:// or https://: status, response time, certificate
	TCP  = "tcp"  // a port accepts connections
	Ping = "ping" // the host answers
	DNS  = "dns"  // the name resolves (to an expected value)
)

// Target is one thing to watch.
type Target struct {
	ID      string        `json:"id"`   // the address as written: the key in the history
	Name    string        `json:"name"` // how it reads on screen
	Kind    string        `json:"kind"`
	Addr    string        `json:"addr"` // URL, host:port, host or name
	Expect  string        `json:"expect,omitempty"`
	Timeout time.Duration `json:"timeout"`
}

// ParseTarget reads one line of a servers file:
//
//	https://example.com [name=Shop] [expect=200] [timeout=5s]
//	tcp://db.internal:5432
//	ping://192.168.0.10
//	dns://example.com expect=93.184.215.14
//
// A bare host:port is TCP, a bare name is HTTPS.
func ParseTarget(line string) (Target, error) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return Target{}, fmt.Errorf("empty")
	}
	t := Target{ID: f[0], Timeout: 10 * time.Second}
	raw := f[0]
	switch {
	case strings.HasPrefix(raw, "http://"), strings.HasPrefix(raw, "https://"):
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return Target{}, fmt.Errorf("%q isn't a URL", raw)
		}
		t.Kind, t.Addr, t.Name = HTTP, raw, u.Host+strings.TrimSuffix(u.Path, "/")
	case strings.HasPrefix(raw, "tcp://"):
		t.Kind, t.Addr = TCP, strings.TrimPrefix(raw, "tcp://")
	case strings.HasPrefix(raw, "ping://"):
		t.Kind, t.Addr = Ping, strings.TrimPrefix(raw, "ping://")
	case strings.HasPrefix(raw, "dns://"):
		t.Kind, t.Addr = DNS, strings.TrimPrefix(raw, "dns://")
	case strings.Contains(raw, "://"):
		return Target{}, fmt.Errorf("%q: use https://, http://, tcp://, ping:// or dns://", raw)
	default:
		if _, p, err := net.SplitHostPort(raw); err == nil && p != "" {
			t.Kind, t.Addr = TCP, raw
		} else {
			t.Kind, t.Addr, t.Name = HTTP, "https://"+raw, raw
			t.ID = t.Addr
		}
	}
	if t.Kind == TCP {
		if _, p, err := net.SplitHostPort(t.Addr); err != nil || p == "" {
			return Target{}, fmt.Errorf("%q: a TCP check needs host:port", raw)
		}
	}
	if t.Addr == "" {
		return Target{}, fmt.Errorf("%q: nothing to check", raw)
	}
	if t.Name == "" {
		t.Name = t.Addr
		if t.Kind != TCP {
			t.Name = t.Kind + " " + t.Addr
		}
	}
	for _, opt := range f[1:] {
		k, v, ok := strings.Cut(opt, "=")
		if !ok {
			return Target{}, fmt.Errorf("%q: options are name=value", opt)
		}
		switch strings.ToLower(k) {
		case "name":
			t.Name = strings.ReplaceAll(v, "_", " ")
		case "expect":
			t.Expect = v
		case "timeout":
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 || d > time.Minute {
				return Target{}, fmt.Errorf("timeout=%s: give a duration up to 1m, like 5s", v)
			}
			t.Timeout = d
		default:
			return Target{}, fmt.Errorf("%q: the options are name=, expect= and timeout=", opt)
		}
	}
	if t.Kind == HTTP && t.Expect != "" {
		if n, err := strconv.Atoi(t.Expect); err != nil || n < 100 || n > 599 {
			return Target{}, fmt.Errorf("expect=%s: an HTTP check expects a status code, like 200", t.Expect)
		}
	}
	return t, nil
}

// Sample is one check of one target.
type Sample struct {
	Time     time.Time `json:"t"`
	ID       string    `json:"id"`
	OK       bool      `json:"ok"`
	Ms       float64   `json:"ms,omitempty"`
	Detail   string    `json:"d,omitempty"`    // status code, or what went wrong
	CertDays int       `json:"cert,omitempty"` // HTTPS: days left on the certificate (0: not checked)
}

// --- the checks ---

// Test seams.
var (
	httpDo = func(ctx context.Context, t Target) (int, *tls.ConnectionState, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", t.Addr, nil)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("User-Agent", UserAgent)
		c := &http.Client{Timeout: t.Timeout, Transport: &http.Transport{DisableKeepAlives: true, Proxy: http.ProxyFromEnvironment}}
		res, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		return res.StatusCode, res.TLS, nil
	}
	dialTCP = func(ctx context.Context, addr string, timeout time.Duration) error {
		d := net.Dialer{Timeout: timeout}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			c.Close()
		}
		return err
	}
	ping = func(ctx context.Context, host string, timeout time.Duration) (float64, error) {
		r := probe.PingBest(ctx, host, []int{443, 80, 22}, 1, timeout, nil)
		if r.Received == 0 {
			if r.Error != "" {
				return 0, errors.New(r.Error)
			}
			return 0, errors.New("no answer")
		}
		return r.AvgMs, nil
	}
	lookupHost = net.DefaultResolver.LookupHost
	now        = time.Now
)

// UserAgent is sent with HTTP checks.
var UserAgent = "netcheck-uptime"

// short makes an error fit a dashboard cell.
func short(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "no such host"):
		return "name doesn't resolve"
	case strings.Contains(s, "refused"):
		return "connection refused"
	case strings.Contains(s, "Timeout") || strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return "no answer in time"
	case strings.Contains(s, "certificate"):
		if strings.Contains(s, "expired") {
			return "certificate expired"
		}
		return "certificate not valid"
	case strings.Contains(s, "unreachable"):
		return "unreachable"
	}
	if len(s) > 60 {
		s = s[:57] + "..."
	}
	return s
}

// Check runs one check.
func Check(ctx context.Context, t Target) Sample {
	s := Sample{ID: t.ID}
	start := now()
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	switch t.Kind {
	case HTTP:
		code, st, err := httpDo(ctx, t)
		s.Ms = float64(now().Sub(start).Microseconds()) / 1000
		if err != nil {
			s.Detail = short(err)
			break
		}
		s.Detail = strconv.Itoa(code)
		if t.Expect != "" {
			s.OK = s.Detail == t.Expect
		} else {
			s.OK = code < 400
		}
		if st != nil && len(st.PeerCertificates) > 0 {
			s.CertDays = int(st.PeerCertificates[0].NotAfter.Sub(now()).Hours() / 24)
			if s.CertDays == 0 {
				s.CertDays = -1 // under a day: keep it distinct from "not checked"
			}
		}
	case TCP:
		err := dialTCP(ctx, t.Addr, t.Timeout)
		s.Ms = float64(now().Sub(start).Microseconds()) / 1000
		s.OK = err == nil
		if err != nil {
			s.Detail = short(err)
		}
	case Ping:
		ms, err := ping(ctx, t.Addr, t.Timeout)
		s.OK, s.Ms = err == nil, ms
		if err != nil {
			s.Detail = short(err)
		}
	case DNS:
		addrs, err := lookupHost(ctx, t.Addr)
		s.Ms = float64(now().Sub(start).Microseconds()) / 1000
		switch {
		case err != nil:
			s.Detail = short(err)
		case t.Expect != "":
			sort.Strings(addrs)
			s.Detail = strings.Join(addrs, ",")
			for _, a := range addrs {
				s.OK = s.OK || a == t.Expect
			}
			if !s.OK {
				s.Detail = "resolves to " + s.Detail + ", not " + t.Expect
			}
		default:
			s.OK, s.Detail = true, strings.Join(addrs, ",")
		}
	}
	s.Time = start
	return s
}

// --- state and events ---

// Event is a change worth telling: down, up again, or a certificate
// running out.
type Event struct {
	Time    time.Time     `json:"time"`
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Kind    string        `json:"kind"` // "down", "up", "cert"
	Text    string        `json:"text"`
	Detail  string        `json:"detail,omitempty"`
	DownFor time.Duration `json:"down_for_ns,omitempty"` // with "up"
}

// State is what's known about one target now.
type State struct {
	Target   Target    `json:"target"`
	Down     bool      `json:"down"`
	Since    time.Time `json:"since"` // when it went up or down (or monitoring began)
	Fails    int       `json:"fails"` // failed checks in a row
	Checks   int       `json:"checks"`
	Good     int       `json:"good"`
	Series   []float64 `json:"series"` // recent response times; -1 = failed
	Last     Sample    `json:"last"`
	CertDays int       `json:"cert_days,omitempty"`
	certWarn bool
}

// Uptime is the share of checks that passed, in percent.
func (s *State) Uptime() float64 {
	if s.Checks == 0 {
		return 0
	}
	return float64(s.Good) / float64(s.Checks) * 100
}

// Monitor keeps the state of every target and decides on events.
type Monitor struct {
	mu        sync.Mutex
	States    []*State
	DownAfter int // failed checks in a row before a target counts as down
	CertDays  int // warn when a certificate has fewer days left
	start     time.Time
}

// NewMonitor starts watching targets.
func NewMonitor(targets []Target, downAfter, certDays int) *Monitor {
	m := &Monitor{DownAfter: max(downAfter, 1), CertDays: certDays, start: now()}
	for _, t := range targets {
		m.States = append(m.States, &State{Target: t, Since: m.start})
	}
	return m
}

// Add records a sample and returns the events it causes.
func (m *Monitor) Add(s Sample) []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var st *State
	for _, x := range m.States {
		if x.Target.ID == s.ID {
			st = x
		}
	}
	if st == nil {
		return nil
	}
	st.Checks++
	st.Last = s
	ms := s.Ms
	if !s.OK {
		ms = -1
		st.Fails++
	} else {
		st.Good++
		st.Fails = 0
	}
	st.Series = append(st.Series, ms)
	if len(st.Series) > 120 {
		st.Series = st.Series[len(st.Series)-120:]
	}
	if s.CertDays != 0 {
		st.CertDays = s.CertDays
	}
	var evs []Event
	ev := func(kind, text string) Event {
		return Event{Time: s.Time, ID: st.Target.ID, Name: st.Target.Name, Kind: kind, Text: text, Detail: s.Detail}
	}
	switch {
	case !st.Down && st.Fails >= m.DownAfter:
		st.Down, st.Since = true, s.Time
		evs = append(evs, ev("down", fmt.Sprintf("%s is down: %s", st.Target.Name, s.Detail)))
	case st.Down && s.OK:
		e := ev("up", "")
		e.DownFor = s.Time.Sub(st.Since)
		e.Text = fmt.Sprintf("%s is back up after %s", st.Target.Name, roundDur(e.DownFor))
		st.Down, st.Since = false, s.Time
		evs = append(evs, e)
	}
	if m.CertDays > 0 && st.CertDays != 0 {
		low := st.CertDays < m.CertDays
		if low && !st.certWarn {
			text := fmt.Sprintf("%s: the certificate expires in %d days", st.Target.Name, max(st.CertDays, 0))
			if st.CertDays < 0 {
				text = st.Target.Name + ": the certificate expires within a day"
			}
			evs = append(evs, ev("cert", text))
		}
		st.certWarn = low
	}
	return evs
}

// Snapshot copies the states for drawing.
func (m *Monitor) Snapshot() []State {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]State, len(m.States))
	for i, s := range m.States {
		out[i] = *s
		out[i].Series = append([]float64(nil), s.Series...)
	}
	return out
}

func roundDur(d time.Duration) time.Duration {
	switch {
	case d >= time.Hour:
		return d.Round(time.Minute)
	case d >= time.Minute:
		return d.Round(time.Second)
	}
	return d.Round(100 * time.Millisecond)
}

// Run checks every target every interval, at most 16 at once, and hands
// each sample to onSample, until ctx ends.
func Run(ctx context.Context, targets []Target, every time.Duration, onSample func(Sample)) {
	round := func() {
		sem := make(chan struct{}, 16)
		var wg sync.WaitGroup
		for _, t := range targets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				s := Check(ctx, t)
				if ctx.Err() == nil {
					onSample(s)
				}
			}()
		}
		wg.Wait()
	}
	round()
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			round()
		}
	}
}
