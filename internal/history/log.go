// Package history stores and analyzes the samples `netcheck watch` records.
//
// The log is JSON Lines, one object per sample:
//
//	{"v":1,"t":"2026-10-13T20:01:05+02:00","gw":2.1,"net":14.2,"dns":11}
//
// v is the format version. gw, net and dns are round trips in ms to the
// router, the internet and the DNS server; -1 means the probe was lost and
// a missing field means that target wasn't measured. Readers skip lines
// with a version they don't know, so the format can grow without breaking
// old logs or old binaries.
package history

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Version is the log format version written by this build.
const Version = 1

// Sample is one tick of measurements.
type Sample struct {
	V   int       `json:"v"`
	T   time.Time `json:"t"`
	GW  *float64  `json:"gw,omitempty"`
	Net *float64  `json:"net,omitempty"`
	DNS *float64  `json:"dns,omitempty"`
}

// Ms boxes a measurement for a Sample field.
func Ms(v float64) *float64 {
	v = math.Round(v*10) / 10 // one decimal keeps lines short
	return &v
}

// Target names one of the measured links.
type Target int

const (
	Gateway Target = iota
	Internet
	DNS
)

// Targets lists every target in display order.
var Targets = []Target{Gateway, Internet, DNS}

func (t Target) String() string {
	switch t {
	case Gateway:
		return "gateway"
	case Internet:
		return "internet"
	}
	return "dns"
}

// Get returns the measurement for t: ms (or -1 if lost) and whether t was
// measured at all.
func (s Sample) Get(t Target) (float64, bool) {
	var p *float64
	switch t {
	case Gateway:
		p = s.GW
	case Internet:
		p = s.Net
	case DNS:
		p = s.DNS
	}
	if p == nil {
		return 0, false
	}
	return *p, true
}

// DefaultMaxBytes is the size at which the log rotates. At one sample every
// 5 seconds that is roughly two weeks, plus two more in the rotated file.
const DefaultMaxBytes = 8 << 20

// DefaultPath is os.UserConfigDir()/netcheck/history.jsonl, overridable
// with NETCHECK_HISTORY.
func DefaultPath() (string, error) {
	if p := os.Getenv("NETCHECK_HISTORY"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netcheck", "history.jsonl"), nil
}

// rotated is where the previous log goes when the current one is full.
func rotated(path string) string { return path + ".1" }

// Writer appends samples to a log, rotating it by size. Only the current
// file and one rotated file are kept.
type Writer struct {
	Path     string
	MaxBytes int64
	f        *os.File
	size     int64
}

// Open opens (or creates) the log for appending.
func Open(path string, maxBytes int64) (*Writer, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	w := &Writer{Path: path, MaxBytes: maxBytes}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return w, w.open()
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, st.Size()
	return nil
}

// Append writes one sample as a single line.
func (w *Writer) Append(s Sample) error {
	if w.f == nil {
		return errors.New("history log is closed")
	}
	s.V = Version
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if w.size > 0 && w.size+int64(len(b)) > w.MaxBytes {
		if err := w.rotate(); err != nil {
			return err
		}
	}
	n, err := w.f.Write(b)
	w.size += int64(n)
	return err
}

func (w *Writer) rotate() error {
	w.f.Close()
	w.f = nil
	// os.Rename replaces an existing target on every OS, Windows included.
	if err := os.Rename(w.Path, rotated(w.Path)); err != nil {
		return err
	}
	return w.open()
}

// Close closes the log.
func (w *Writer) Close() error {
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// ReadResult is what Read found in the log.
type ReadResult struct {
	Samples []Sample
	Skipped int // unreadable lines or lines from a newer format version
}

// Read loads the rotated and current log, oldest first. A missing log is
// not an error; it just has no samples.
func Read(path string) (ReadResult, error) {
	var res ReadResult
	for _, p := range []string{rotated(path), path} {
		if err := readFile(p, &res); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return res, err
		}
	}
	sort.SliceStable(res.Samples, func(i, j int) bool { return res.Samples[i].T.Before(res.Samples[j].T) })
	return res, nil
}

func readFile(path string, res *ReadResult) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var s Sample
		if err := json.Unmarshal(line, &s); err != nil || s.V != Version || s.T.IsZero() {
			res.Skipped++ // a torn last line, or a format we don't know
			continue
		}
		res.Samples = append(res.Samples, s)
	}
	return sc.Err()
}
