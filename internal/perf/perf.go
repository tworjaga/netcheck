// Package perf measures throughput between two machines, iperf-style: a
// server on one, a client on the other. TCP in each direction over one or
// more streams, and UDP at a chosen rate for loss, reordering and jitter.
package perf

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultPort is where a server listens unless told otherwise.
const DefaultPort = 5205

const (
	magic       = "NETCHECK-PERF/1"
	maxDuration = 60 * time.Second
	maxStreams  = 16
	sampleEvery = 250 * time.Millisecond
	bufSize     = 128 << 10
)

// Tests.
const (
	TCPDown = "tcp-down" // server sends, client receives
	TCPUp   = "tcp-up"   // client sends, server receives
	UDP     = "udp"      // client sends at Rate, server counts
)

// Request is what a client asks for.
type Request struct {
	Test     string        `json:"test"`
	Streams  int           `json:"streams"`
	Duration time.Duration `json:"duration"`
	Rate     int64         `json:"rate,omitempty"` // UDP: bits per second
	Size     int           `json:"size,omitempty"` // UDP: payload bytes
	Last     bool          `json:"last,omitempty"` // the client's last test: a --once server stops after it
}

type hello struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Session string `json:"session,omitempty"`
	UDPPort int    `json:"udp_port,omitempty"`
}

// UDPStats is what the receiver saw of a UDP test.
type UDPStats struct {
	Sent       int     `json:"sent"`
	Received   int     `json:"received"`
	Lost       int     `json:"lost"`
	OutOfOrder int     `json:"out_of_order"`
	LossPct    float64 `json:"loss_pct"`
	JitterMs   float64 `json:"jitter_ms"`
}

// Result is one test, measured by the receiving side.
type Result struct {
	Test    string        `json:"test"`
	Streams int           `json:"streams"`
	Bytes   int64         `json:"bytes"`
	Elapsed time.Duration `json:"elapsed_ns"`
	Mbps    float64       `json:"mbps"`
	Samples []float64     `json:"samples_mbps"` // per 250 ms
	UDP     *UDPStats     `json:"udp,omitempty"`
	Error   string        `json:"error,omitempty"`
}

func mbps(bytes int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(bytes) * 8 / d.Seconds() / 1e6
}

// meter counts bytes and keeps a sample per interval.
type meter struct {
	n       atomic.Int64
	mu      sync.Mutex
	samples []float64
	first   time.Time
	last    time.Time
	stop    chan struct{}
	onTick  func(float64)
}

func newMeter(onTick func(float64)) *meter {
	m := &meter{stop: make(chan struct{}), onTick: onTick}
	go func() {
		t := time.NewTicker(sampleEvery)
		defer t.Stop()
		var prev int64
		for {
			select {
			case <-m.stop:
				return
			case <-t.C:
				cur := m.n.Load()
				if cur == 0 {
					continue // not started yet
				}
				v := mbps(cur-prev, sampleEvery)
				prev = cur
				m.mu.Lock()
				m.samples = append(m.samples, v)
				m.mu.Unlock()
				if m.onTick != nil {
					m.onTick(v)
				}
			}
		}
	}()
	return m
}

func (m *meter) add(n int) {
	now := time.Now()
	m.mu.Lock()
	if m.first.IsZero() {
		m.first = now
	}
	m.last = now
	m.mu.Unlock()
	m.n.Add(int64(n))
}

func (m *meter) result(test string, streams int) Result {
	close(m.stop)
	m.mu.Lock()
	defer m.mu.Unlock()
	r := Result{Test: test, Streams: streams, Bytes: m.n.Load(), Samples: append([]float64(nil), m.samples...)}
	if !m.first.IsZero() {
		r.Elapsed = m.last.Sub(m.first)
	}
	r.Mbps = mbps(r.Bytes, r.Elapsed)
	return r
}

// count reads a stream to its end, feeding the meter.
func count(r io.Reader, m *meter) {
	buf := make([]byte, bufSize)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			m.add(n)
		}
		if err != nil {
			return
		}
	}
}

// send writes to a stream until the deadline.
func send(w net.Conn, until time.Time, m *meter) {
	buf := make([]byte, bufSize)
	rand.Read(buf) // incompressible, in case something on the way compresses
	w.SetWriteDeadline(until)
	for time.Now().Before(until) {
		n, err := w.Write(buf)
		if m != nil && n > 0 {
			m.add(n)
		}
		if err != nil {
			return
		}
	}
}

// --- UDP packets: sequence number, send time, padding ---

func udpPacket(seq uint64, size int) []byte {
	b := make([]byte, max(size, 16))
	binary.BigEndian.PutUint64(b, seq)
	binary.BigEndian.PutUint64(b[8:], uint64(time.Now().UnixNano()))
	return b
}

// udpCounter tracks arrivals: count, highest sequence, reordering, and
// jitter as RFC 3550 defines it (the clocks' offset cancels out).
type udpCounter struct {
	received, outOfOrder int
	maxSeq               uint64
	seen                 bool
	jitter               float64 // ns
	lastTransit          float64
	bytes                int64
}

func (c *udpCounter) packet(b []byte, at time.Time) {
	if len(b) < 16 {
		return
	}
	seq := binary.BigEndian.Uint64(b)
	sent := int64(binary.BigEndian.Uint64(b[8:]))
	transit := float64(at.UnixNano() - sent)
	if c.seen {
		d := math.Abs(transit - c.lastTransit)
		c.jitter += (d - c.jitter) / 16
		if seq < c.maxSeq {
			c.outOfOrder++
		}
	}
	if !c.seen || seq > c.maxSeq {
		c.maxSeq = seq
	}
	c.seen, c.lastTransit = true, transit
	c.received++
	c.bytes += int64(len(b))
}

func (c *udpCounter) stats(sent int) *UDPStats {
	s := &UDPStats{Sent: sent, Received: c.received, OutOfOrder: c.outOfOrder, JitterMs: c.jitter / 1e6}
	if sent > 0 {
		s.Lost = max(0, sent-c.received)
		s.LossPct = float64(s.Lost) / float64(sent) * 100
	}
	return s
}

// --- the server ---

type session struct {
	id      string
	req     Request
	streams chan net.Conn
}

// Server answers perf clients.
type Server struct {
	mu       sync.Mutex
	sessions map[string]*session
	// Log receives one line per finished test.
	Log func(peer string, r Result)
}

// Serve listens on addr until ctx ends; with once, after the first client
// session.
func (s *Server) Serve(ctx context.Context, ln net.Listener, once bool) error {
	s.sessions = map[string]*session{}
	done := make(chan struct{}, 1)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			if s.handle(ctx, c) && once {
				select {
				case done <- struct{}{}:
				default:
				}
			}
		}()
	}
}

// handle reads a connection's first line: a control session, or a data
// stream for one. It reports whether a client's last test finished.
func (s *Server) handle(ctx context.Context, c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, magic+" ") {
		c.Close() // not a netcheck client
		return false
	}
	f := strings.Fields(line)
	switch {
	case len(f) == 2 && f[1] == "CONTROL":
		return s.control(ctx, c, br)
	case len(f) == 4 && f[1] == "DATA":
		s.mu.Lock()
		sess := s.sessions[f[2]]
		s.mu.Unlock()
		if sess == nil {
			c.Close()
			return false
		}
		c.SetReadDeadline(time.Time{})
		sess.streams <- &bufConn{Conn: c, r: br}
	default:
		c.Close()
	}
	return false
}

// bufConn keeps what bufio already read.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func writeJSON(w io.Writer, v any) error {
	b, _ := json.Marshal(v)
	_, err := w.Write(append(b, '\n'))
	return err
}

// control runs one test and reports whether it was the client's last.
func (s *Server) control(ctx context.Context, c net.Conn, br *bufio.Reader) bool {
	defer c.Close()
	line, err := br.ReadString('\n')
	if err != nil {
		return false
	}
	var req Request
	if json.Unmarshal([]byte(line), &req) != nil {
		writeJSON(c, hello{Error: "bad request"})
		return false
	}
	if req.Duration <= 0 || req.Duration > maxDuration {
		req.Duration = min(max(req.Duration, time.Second), maxDuration)
	}
	req.Streams = min(max(req.Streams, 1), maxStreams)
	id := make([]byte, 8)
	rand.Read(id)
	sess := &session{id: hex.EncodeToString(id), req: req, streams: make(chan net.Conn, maxStreams)}
	h := hello{OK: true, Session: sess.id}
	var uc *net.UDPConn
	switch req.Test {
	case TCPDown, TCPUp:
	case UDP:
		uc, err = net.ListenUDP("udp", &net.UDPAddr{})
		if err != nil {
			writeJSON(c, hello{Error: "couldn't open a UDP port: " + err.Error()})
			return false
		}
		defer uc.Close()
		h.UDPPort = uc.LocalAddr().(*net.UDPAddr).Port
	default:
		writeJSON(c, hello{Error: "unknown test " + req.Test})
		return false
	}
	s.mu.Lock()
	s.sessions[sess.id] = sess
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.sessions, sess.id)
		s.mu.Unlock()
	}()
	c.SetReadDeadline(time.Time{})
	if writeJSON(c, h) != nil {
		return false
	}
	peer := c.RemoteAddr().String()
	var res Result
	switch req.Test {
	case TCPDown:
		conns := s.collect(sess, req.Streams)
		until := time.Now().Add(req.Duration)
		var wg sync.WaitGroup
		for _, d := range conns {
			wg.Add(1)
			go func() { defer wg.Done(); send(d, until, nil); d.Close() }()
		}
		wg.Wait()
		// The client measured it; its result goes in the log.
		res = Result{Test: TCPDown, Streams: len(conns)}
		c.SetReadDeadline(time.Now().Add(15 * time.Second))
		if l, err := br.ReadString('\n'); err == nil {
			json.Unmarshal([]byte(l), &res)
		}
	case TCPUp:
		conns := s.collect(sess, req.Streams)
		m := newMeter(nil)
		var wg sync.WaitGroup
		for _, d := range conns {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.SetReadDeadline(time.Now().Add(req.Duration + 10*time.Second))
				count(d, m)
				d.Close()
			}()
		}
		wg.Wait()
		res = m.result(TCPUp, len(conns))
		writeJSON(c, res)
	case UDP:
		var ctr udpCounter
		m := newMeter(nil)
		stop := make(chan struct{})
		var sent int
		go func() {
			// The client says how many it sent, then the counting stops.
			c.SetReadDeadline(time.Now().Add(req.Duration + 10*time.Second))
			if l, err := br.ReadString('\n'); err == nil {
				sent, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(l, "SENT ")))
			}
			time.Sleep(500 * time.Millisecond) // stragglers
			close(stop)
			uc.SetReadDeadline(time.Now())
		}()
		buf := make([]byte, 65536)
		for {
			uc.SetReadDeadline(time.Now().Add(req.Duration + 10*time.Second))
			n, _, err := uc.ReadFromUDP(buf)
			if err != nil {
				break
			}
			ctr.packet(buf[:n], time.Now())
			m.add(n)
		}
		<-stop
		res = m.result(UDP, 1)
		res.UDP = ctr.stats(sent)
		writeJSON(c, res)
	}
	if s.Log != nil {
		s.Log(peer, res)
	}
	return req.Last
}

// collect waits for a session's data streams to arrive.
func (s *Server) collect(sess *session, n int) []net.Conn {
	var conns []net.Conn
	timeout := time.After(5 * time.Second)
	for len(conns) < n {
		select {
		case c := <-sess.streams:
			conns = append(conns, c)
		case <-timeout:
			return conns
		}
	}
	return conns
}

// --- the client ---

// dial is a test seam.
var dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, network, addr)
}

func explain(err error, addr string) error {
	var op *net.OpError
	switch {
	case errors.As(err, &op) && strings.Contains(err.Error(), "refused"):
		return fmt.Errorf("nothing listens on %s; start `netcheck perf --server` there first", addr)
	case errors.As(err, &op) && op.Timeout():
		return fmt.Errorf("no answer from %s; a firewall may block the port", addr)
	}
	return err
}

// Run does one test against the server at addr. progress, if set, gets
// the receiving rate every 250 ms (for uploads, the sending rate).
func Run(ctx context.Context, addr string, req Request, progress func(float64)) Result {
	r := Result{Test: req.Test, Streams: req.Streams}
	c, err := dial(ctx, "tcp", addr)
	if err != nil {
		r.Error = explain(err, addr).Error()
		return r
	}
	defer c.Close()
	fmt.Fprintf(c, "%s CONTROL\n", magic)
	writeJSON(c, req)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		r.Error = "the other side isn't a netcheck perf server"
		return r
	}
	var h hello
	if json.Unmarshal([]byte(line), &h) != nil || !h.OK {
		r.Error = "the server refused: " + h.Error
		if h.Error == "" {
			r.Error = "the other side isn't a netcheck perf server"
		}
		return r
	}
	c.SetReadDeadline(time.Time{})
	host, _, _ := net.SplitHostPort(addr)
	openStreams := func() ([]net.Conn, error) {
		var conns []net.Conn
		for i := 0; i < req.Streams; i++ {
			d, err := dial(ctx, "tcp", addr)
			if err != nil {
				for _, x := range conns {
					x.Close()
				}
				return nil, err
			}
			fmt.Fprintf(d, "%s DATA %s %d\n", magic, h.Session, i)
			conns = append(conns, d)
		}
		return conns, nil
	}
	switch req.Test {
	case TCPDown:
		conns, err := openStreams()
		if err != nil {
			r.Error = explain(err, addr).Error()
			return r
		}
		m := newMeter(progress)
		var wg sync.WaitGroup
		for _, d := range conns {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d.SetReadDeadline(time.Now().Add(req.Duration + 10*time.Second))
				count(d, m)
				d.Close()
			}()
		}
		wg.Wait()
		r = m.result(TCPDown, len(conns))
		writeJSON(c, r)
	case TCPUp:
		conns, err := openStreams()
		if err != nil {
			r.Error = explain(err, addr).Error()
			return r
		}
		m := newMeter(progress)
		until := time.Now().Add(req.Duration)
		var wg sync.WaitGroup
		for _, d := range conns {
			wg.Add(1)
			go func() {
				defer wg.Done()
				send(d, until, m)
				if tc, ok := d.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
				d.Close()
			}()
		}
		wg.Wait()
		m.result(TCPUp, len(conns)) // stop the ticker; the server's count is the result
		c.SetReadDeadline(time.Now().Add(15 * time.Second))
		line, err := br.ReadString('\n')
		if err != nil || json.Unmarshal([]byte(line), &r) != nil {
			r = Result{Test: TCPUp, Streams: req.Streams, Error: "the server didn't send its count"}
		}
	case UDP:
		u, err := dial(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(h.UDPPort)))
		if err != nil {
			r.Error = err.Error()
			return r
		}
		defer u.Close()
		size := max(req.Size, 64)
		every := time.Duration(float64(size*8) / float64(max(req.Rate, 1)) * float64(time.Second))
		start := time.Now()
		end := start.Add(req.Duration)
		var seq uint64
		m := newMeter(progress)
		for now := time.Now(); now.Before(end) && ctx.Err() == nil; now = time.Now() {
			// Send what's due by now, then sleep a little: steady, not bursty.
			due := uint64(now.Sub(start) / every)
			for ; seq <= due && seq < due+1000; seq++ {
				b := udpPacket(seq, size)
				if _, err := u.Write(b); err == nil {
					m.add(len(b))
				}
			}
			time.Sleep(time.Millisecond)
		}
		m.result(UDP, 1)
		fmt.Fprintf(c, "SENT %d\n", seq)
		c.SetReadDeadline(time.Now().Add(15 * time.Second))
		line, err := br.ReadString('\n')
		if err != nil || json.Unmarshal([]byte(line), &r) != nil {
			r = Result{Test: UDP, Error: "the server didn't send its count"}
		}
	}
	return r
}
