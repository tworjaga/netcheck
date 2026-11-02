package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SpeedConfig controls a speed test. The defaults use Cloudflare's public
// speed-test endpoints (__down and __up), which are free and need no key.
type SpeedConfig struct {
	BaseURL     string
	DownStreams int
	UpStreams   int
	Duration    time.Duration // per direction
	Warmup      time.Duration // ignored at the start of each direction (TCP slow start)
	IdleProbes  int
}

// DefaultSpeedConfig returns the settings used by `netcheck speed`.
func DefaultSpeedConfig() SpeedConfig {
	return SpeedConfig{
		BaseURL:     "https://speed.cloudflare.com",
		DownStreams: 4,
		UpStreams:   3,
		Duration:    8 * time.Second,
		Warmup:      1500 * time.Millisecond,
		IdleProbes:  10,
	}
}

// SpeedResult is the outcome of a speed test.
type SpeedResult struct {
	Server       string  `json:"server,omitempty"`
	DownMbps     float64 `json:"down_mbps"`
	UpMbps       float64 `json:"up_mbps"`
	IdleMs       float64 `json:"idle_latency_ms"`
	IdleJitterMs float64 `json:"idle_jitter_ms"`
	DownLoadedMs float64 `json:"latency_during_download_ms,omitempty"`
	UpLoadedMs   float64 `json:"latency_during_upload_ms,omitempty"`
	BloatMs      float64 `json:"bufferbloat_ms"`
	Grade        string  `json:"bufferbloat_grade,omitempty"`
	Error        string  `json:"error,omitempty"`
	Partial      string  `json:"partial,omitempty"` // which direction failed, if one did
}

// SpeedProgress is a live update during the test.
type SpeedProgress struct {
	Phase     string // "latency", "download", "upload"
	Done      bool   // the phase finished; Mbps and LatencyMs are final values
	Server    string // set on the latency "Done" event
	Mbps      float64
	LatencyMs float64 // latest probe while running; the median when Done
}

// BloatGrade maps added latency under load to a grade. Thresholds: A < 30 ms,
// B < 60, C < 120, D < 250, F beyond.
func BloatGrade(addedMs float64) string {
	switch {
	case addedMs < 30:
		return "A"
	case addedMs < 60:
		return "B"
	case addedMs < 120:
		return "C"
	case addedMs < 250:
		return "D"
	}
	return "F"
}

// newSpeedClient builds an HTTP/1.1 client. HTTP/2 would multiplex all
// streams onto one TCP connection, hiding the congestion we want to load.
func newSpeedClient(maxConns int) *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 6 * time.Second,
		MaxConnsPerHost:       maxConns,
		MaxIdleConnsPerHost:   maxConns,
		DisableCompression:    true,
	}}
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	return c[len(c)/2]
}

// latencyProbe times a tiny request on an already-open connection.
func latencyProbe(ctx context.Context, c *http.Client, base string) (float64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/__down?bytes=0", nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", userAgent)
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("http %d", resp.StatusCode)
	}
	colo := resp.Header.Get("Cf-Meta-Colo")
	if colo == "" {
		colo = rayColo(resp.Header.Get("Cf-Ray"))
	}
	return float64(time.Since(start).Microseconds()) / 1000, colo, nil
}

// rayColo reads the data centre from a CF-Ray header ("a4a53e03f8885ba7-VIE").
// The speed test no longer sends Cf-Meta-Colo; the ray ID still ends in it.
func rayColo(ray string) string {
	i := strings.LastIndexByte(ray, '-')
	if i < 0 || len(ray)-i-1 != 3 {
		return ""
	}
	c := ray[i+1:]
	for _, r := range c {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return c
}

type zeroReader struct {
	ctx     context.Context
	left    int64
	counter *atomic.Int64
}

func (z *zeroReader) Read(p []byte) (int, error) {
	if err := z.ctx.Err(); err != nil {
		return 0, err
	}
	if z.left <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > 32<<10 {
		n = 32 << 10
	}
	if n > z.left {
		n = z.left
	}
	z.left -= n
	z.counter.Add(n)
	return int(n), nil
}

const chunkBytes = 25_000_000

func downloadWorker(ctx context.Context, c *http.Client, base string, counter *atomic.Int64) {
	buf := make([]byte, 64<<10)
	for ctx.Err() == nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/__down?bytes=%d", base, chunkBytes), nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := c.Do(req)
		if err != nil {
			if ctx.Err() == nil {
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}
		for {
			n, err := resp.Body.Read(buf)
			counter.Add(int64(n))
			if err != nil {
				break
			}
		}
		resp.Body.Close()
	}
}

func uploadWorker(ctx context.Context, c *http.Client, base string, counter *atomic.Int64) {
	for ctx.Err() == nil {
		body := &zeroReader{ctx: ctx, left: chunkBytes, counter: counter}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/__up", body)
		if err != nil {
			return
		}
		req.ContentLength = chunkBytes
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("User-Agent", userAgent)
		resp, err := c.Do(req)
		if err != nil {
			if ctx.Err() == nil {
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// load saturates the link in one direction and measures throughput plus the
// latency seen by a separate, already-warm connection while it's busy.
func load(ctx context.Context, cfg SpeedConfig, phase string, streams int, worker func(context.Context, *http.Client, string, *atomic.Int64), lat *http.Client, progress func(SpeedProgress)) (mbps float64, loaded []float64, err error) {
	runCtx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()
	client := newSpeedClient(streams)
	defer client.CloseIdleConnections()

	var counter atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); worker(runCtx, client, cfg.BaseURL, &counter) }()
	}

	var latMu sync.Mutex
	var lastLat float64
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		for runCtx.Err() == nil {
			if ms, _, e := latencyProbe(runCtx, lat, cfg.BaseURL); e == nil && time.Since(start) > cfg.Warmup/2 {
				latMu.Lock()
				loaded = append(loaded, ms)
				lastLat = ms
				latMu.Unlock()
			}
			select {
			case <-runCtx.Done():
			case <-time.After(150 * time.Millisecond):
			}
		}
	}()

	type sample struct {
		t time.Time
		b int64
	}
	start := time.Now()
	var base *sample
	var recent []sample
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
loop:
	for {
		select {
		case <-runCtx.Done():
			break loop
		case now := <-tick.C:
			s := sample{now, counter.Load()}
			if base == nil && now.Sub(start) >= cfg.Warmup {
				b := s
				base = &b
			}
			recent = append(recent, s)
			if len(recent) > 5 {
				recent = recent[1:]
			}
			if progress != nil && len(recent) > 1 {
				a, z := recent[0], recent[len(recent)-1]
				latMu.Lock()
				ll := lastLat
				latMu.Unlock()
				progress(SpeedProgress{Phase: phase, Mbps: float64(z.b-a.b) * 8 / z.t.Sub(a.t).Seconds() / 1e6, LatencyMs: ll})
			}
		}
	}
	endBytes, endTime := counter.Load(), time.Now()
	cancel()
	wg.Wait()
	if ctx.Err() != nil {
		return 0, nil, ctx.Err()
	}
	if base == nil || endBytes <= base.b || !endTime.After(base.t) {
		return 0, loaded, errors.New("no data received")
	}
	mbps = float64(endBytes-base.b) * 8 / endTime.Sub(base.t).Seconds() / 1e6
	return mbps, loaded, nil
}

// RunSpeed measures idle latency, download, upload and latency under load,
// then grades bufferbloat. It never blocks past its configured durations
// plus a few seconds, and stops immediately when ctx is cancelled.
func RunSpeed(ctx context.Context, cfg SpeedConfig, progress func(SpeedProgress)) SpeedResult {
	var res SpeedResult
	emit := func(p SpeedProgress) {
		if progress != nil {
			progress(p)
		}
	}
	lat := newSpeedClient(1)
	defer lat.CloseIdleConnections()

	var idle []float64
	for i := 0; i < cfg.IdleProbes+1 && ctx.Err() == nil; i++ {
		pc, cancel := context.WithTimeout(ctx, 4*time.Second)
		ms, colo, err := latencyProbe(pc, lat, cfg.BaseURL)
		cancel()
		if err != nil {
			if i == 0 {
				res.Error = "couldn't reach the speed test server (offline, or blocked)"
				return res
			}
			continue
		}
		if colo != "" {
			res.Server = "Cloudflare " + colo
		}
		if i > 0 { // the first probe includes connection setup
			idle = append(idle, ms)
			emit(SpeedProgress{Phase: "latency", LatencyMs: ms})
		}
		select {
		case <-ctx.Done():
		case <-time.After(80 * time.Millisecond):
		}
	}
	if ctx.Err() != nil {
		res.Error = "interrupted"
		return res
	}
	if len(idle) == 0 {
		res.Error = "couldn't measure latency to the speed test server"
		return res
	}
	res.IdleMs = median(idle)
	emit(SpeedProgress{Phase: "latency", Done: true, LatencyMs: res.IdleMs, Server: res.Server})
	var jsum float64
	for i := 1; i < len(idle); i++ {
		jsum += math.Abs(idle[i] - idle[i-1])
	}
	if len(idle) > 1 {
		res.IdleJitterMs = jsum / float64(len(idle)-1)
	}

	down, dl, derr := load(ctx, cfg, "download", cfg.DownStreams, downloadWorker, lat, progress)
	if ctx.Err() != nil {
		res.Error = "interrupted"
		return res
	}
	if derr != nil {
		res.Partial = "download failed: " + derr.Error()
	}
	res.DownMbps, res.DownLoadedMs = down, median(dl)
	emit(SpeedProgress{Phase: "download", Done: true, Mbps: down, LatencyMs: res.DownLoadedMs})

	up, ul, uerr := load(ctx, cfg, "upload", cfg.UpStreams, uploadWorker, lat, progress)
	if ctx.Err() != nil {
		res.Error = "interrupted"
		return res
	}
	if uerr != nil {
		if res.Partial != "" {
			res.Partial += "; "
		}
		res.Partial += "upload failed: " + uerr.Error()
	}
	res.UpMbps, res.UpLoadedMs = up, median(ul)
	emit(SpeedProgress{Phase: "upload", Done: true, Mbps: up, LatencyMs: res.UpLoadedMs})

	worst := math.Max(res.DownLoadedMs, res.UpLoadedMs)
	if worst > 0 {
		res.BloatMs = math.Max(0, worst-res.IdleMs)
		res.Grade = BloatGrade(res.BloatMs)
	}
	if derr != nil && uerr != nil {
		res.Error = "the speed test couldn't move any data"
	}
	return res
}
