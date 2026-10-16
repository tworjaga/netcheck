package uptime

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// DefaultPath is os.UserConfigDir()/netcheck/uptime.jsonl, or
// NETCHECK_UPTIME_LOG.
func DefaultPath() (string, error) {
	if p := os.Getenv("NETCHECK_UPTIME_LOG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netcheck", "uptime.jsonl"), nil
}

// maxLog is the size at which the log rotates; one old file is kept.
const maxLog = 20 << 20

// Log appends samples, one JSON object per line.
type Log struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

// OpenLog opens (or creates) the history for appending.
func OpenLog(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	l := &Log{path: path}
	return l, l.open()
}

func (l *Log) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	l.f, l.size = f, st.Size()
	return nil
}

// Append writes one sample.
func (l *Log) Append(s Sample) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, _ := json.Marshal(s)
	b = append(b, '\n')
	if l.size+int64(len(b)) > maxLog {
		l.f.Close()
		os.Rename(l.path, l.path+".1")
		if err := l.open(); err != nil {
			return err
		}
	}
	n, err := l.f.Write(b)
	l.size += int64(n)
	return err
}

// Close closes the log.
func (l *Log) Close() error { return l.f.Close() }

// ReadLog reads the history (the rotated file first), keeping samples
// from since on. Lines it can't read are skipped.
func ReadLog(path string, since time.Time) ([]Sample, error) {
	var out []Sample
	found := false
	for _, p := range []string{path + ".1", path} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		found = true
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var s Sample
			if json.Unmarshal(sc.Bytes(), &s) == nil && !s.Time.Before(since) {
				out = append(out, s)
			}
		}
		f.Close()
	}
	if !found {
		return nil, os.ErrNotExist
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out, nil
}

// Outage is a stretch of failed checks.
type Outage struct {
	Start  time.Time     `json:"start"`
	End    time.Time     `json:"end"` // the first good check after, or the last bad one if it hasn't ended
	Length time.Duration `json:"length_ns"`
	Ended  bool          `json:"ended"`
	Detail string        `json:"detail"`
}

// Summary is one target's history over a period.
type Summary struct {
	ID       string        `json:"id"`
	Checks   int           `json:"checks"`
	Good     int           `json:"good"`
	Uptime   float64       `json:"uptime_pct"`
	AvgMs    float64       `json:"avg_ms"`
	Outages  []Outage      `json:"outages"`
	Down     time.Duration `json:"down_ns"`
	CertDays int           `json:"cert_days,omitempty"`
}

// Summarize groups samples by target. An outage is downAfter or more
// failed checks in a row; shorter runs only lower the uptime.
func Summarize(samples []Sample, downAfter int) map[string]*Summary {
	out := map[string]*Summary{}
	runs := map[string][]Sample{}
	sums := map[string]float64{}
	closeRun := func(id string, endAt time.Time, ended bool) {
		r := runs[id]
		if len(r) >= downAfter {
			o := Outage{Start: r[0].Time, End: endAt, Ended: ended, Detail: r[len(r)-1].Detail}
			if !ended {
				o.End = r[len(r)-1].Time
			}
			o.Length = o.End.Sub(o.Start)
			out[id].Outages = append(out[id].Outages, o)
			out[id].Down += o.Length
		}
		runs[id] = nil
	}
	for _, s := range samples {
		sm := out[s.ID]
		if sm == nil {
			sm = &Summary{ID: s.ID}
			out[s.ID] = sm
		}
		sm.Checks++
		if s.CertDays != 0 {
			sm.CertDays = s.CertDays
		}
		if s.OK {
			sm.Good++
			sums[s.ID] += s.Ms
			if len(runs[s.ID]) > 0 {
				closeRun(s.ID, s.Time, true)
			}
		} else {
			runs[s.ID] = append(runs[s.ID], s)
		}
	}
	for id := range out {
		if len(runs[id]) > 0 {
			closeRun(id, time.Time{}, false)
		}
		sm := out[id]
		if sm.Checks > 0 {
			sm.Uptime = float64(sm.Good) / float64(sm.Checks) * 100
		}
		if sm.Good > 0 {
			sm.AvgMs = sums[id] / float64(sm.Good)
		}
	}
	return out
}
