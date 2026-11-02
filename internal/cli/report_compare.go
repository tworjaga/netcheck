package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"time"
)

// compareRow is one measurement in an earlier report and in this one.
type compareRow struct {
	Metric string  `json:"metric"`
	Unit   string  `json:"unit"`
	Before float64 `json:"before"`
	After  float64 `json:"after"`
	Change string  `json:"change"` // better, worse, same
}

// comparison is a report set against an earlier one: did a change help?
type comparison struct {
	Since         time.Time    `json:"since"`
	BeforeVerdict string       `json:"before_verdict"`
	Rows          []compareRow `json:"rows"`
}

// metric is one number a report can be compared on.
type metric struct {
	name, unit   string
	value        float64
	higherBetter bool
}

// reportMetrics lists the comparable numbers in a report, skipping what it
// didn't measure.
func reportMetrics(r reportData) []metric {
	var ms []metric
	add := func(name, unit string, v float64, higherBetter bool) {
		ms = append(ms, metric{name, unit, v, higherBetter})
	}
	d := r.Checks
	if g := d.Gateway; g != nil && g.Received > 0 {
		add("Router latency", "ms", g.AvgMs, false)
		add("Router loss", "%", g.LossPct, false)
	}
	if n := d.Internet; n != nil && n.Received > 0 {
		add("Internet latency", "ms", n.AvgMs, false)
		add("Internet jitter", "ms", n.JitterMs, false)
		add("Internet loss", "%", n.LossPct, false)
	}
	if len(d.DNS) > 0 && d.DNS[0].Answered > 0 {
		add("Your DNS", "ms", d.DNS[0].MedianMs, false)
	}
	if w := d.Wifi; w != nil && w.Connected && w.SignalDBm != 0 {
		add("Wi-Fi signal", "dBm", float64(w.SignalDBm), true)
	}
	if s := d.Speed; s != nil && s.Error == "" {
		if s.DownMbps > 0 {
			add("Download", "Mbps", s.DownMbps, true)
		}
		if s.UpMbps > 0 {
			add("Upload", "Mbps", s.UpMbps, true)
		}
		if s.IdleMs > 0 {
			add("Idle latency", "ms", s.IdleMs, false)
		}
		if s.Grade != "" {
			add("Bufferbloat", "ms", s.BloatMs, false)
		}
	}
	return ms
}

// sameWithin is how far a value may move and still count as "about the
// same": 10% of the earlier value, but never less than a unit's floor, so
// ordinary jitter doesn't read as progress.
func sameWithin(unit string, before float64) float64 {
	floor := map[string]float64{"ms": 3, "%": 0.5, "dBm": 3, "Mbps": 1}[unit]
	return math.Max(floor, math.Abs(before)*0.1)
}

// compareReports sets now against an earlier report, metric by metric.
func compareReports(before, now reportData) comparison {
	c := comparison{Since: before.Generated, BeforeVerdict: before.Verdict.Message}
	prev := map[string]metric{}
	for _, m := range reportMetrics(before) {
		prev[m.name] = m
	}
	for _, m := range reportMetrics(now) {
		p, ok := prev[m.name]
		if !ok {
			continue
		}
		row := compareRow{Metric: m.name, Unit: m.unit, Before: p.value, After: m.value, Change: "same"}
		if diff := m.value - p.value; math.Abs(diff) > sameWithin(m.unit, p.value) {
			if (diff > 0) == m.higherBetter {
				row.Change = "better"
			} else {
				row.Change = "worse"
			}
		}
		c.Rows = append(c.Rows, row)
	}
	return c
}

// fmtMetric renders a value in its unit, the way the rest of netcheck does.
func fmtMetric(v float64, unit string) string {
	switch unit {
	case "ms":
		return fmtMs(v)
	case "Mbps":
		return fmtMbps(v)
	case "dBm":
		return fmt.Sprintf("%.0f dBm", v)
	case "%":
		return fmt.Sprintf("%.1f%%", v)
	}
	return fmt.Sprintf("%g %s", v, unit)
}

// changeWord is the last column of the comparison table.
func changeWord(c string) string {
	if c == "same" {
		return "about the same"
	}
	return c
}

// compareSummary counts the rows, for the line printed after saving.
func compareSummary(c comparison) string {
	n := map[string]int{}
	for _, r := range c.Rows {
		n[r.Change]++
	}
	return fmt.Sprintf("Compared with %s: %d better, %d worse, %d about the same.",
		c.Since.Format("Mon Jan 2 15:04"), n["better"], n["worse"], n["same"])
}

// lastReportPath is where each report keeps its numbers for the next
// `report --compare last`: os.UserConfigDir()/netcheck/last-report.json,
// overridable with NETCHECK_LAST_REPORT.
func lastReportPath() (string, error) {
	if p := os.Getenv("NETCHECK_LAST_REPORT"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netcheck", "last-report.json"), nil
}

// errNoLastReport means --compare last was asked for before any report ran.
var errNoLastReport = errors.New("no earlier report yet: run netcheck report once, make your change, then run netcheck report --compare last")

// loadReport reads an earlier report: "last" for the one saved
// automatically, otherwise a file from report --format json.
func loadReport(which string) (reportData, error) {
	path := which
	if which == "last" {
		p, err := lastReportPath()
		if err != nil {
			return reportData{}, err
		}
		path = p
	}
	b, err := os.ReadFile(path)
	if which == "last" && errors.Is(err, fs.ErrNotExist) {
		return reportData{}, errNoLastReport
	}
	if err != nil {
		return reportData{}, err
	}
	var r reportData
	if err := json.Unmarshal(b, &r); err != nil || r.Generated.IsZero() {
		return reportData{}, fmt.Errorf("%s isn't a netcheck JSON report (make one with netcheck report --format json)", path)
	}
	return r, nil
}

// saveLastReport keeps this report's numbers for the next comparison.
func saveLastReport(r reportData) error {
	path, err := lastReportPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
