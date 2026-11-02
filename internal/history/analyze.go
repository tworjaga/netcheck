package history

import (
	"math"
	"sort"
	"time"
)

// Stats summarizes one target over a period.
type Stats struct {
	Samples  int     `json:"samples"`
	Lost     int     `json:"lost"`
	LossPct  float64 `json:"loss_pct"`
	MedianMs float64 `json:"median_ms"`
	P95Ms    float64 `json:"p95_ms"`
}

// Outage is a stretch where the internet stopped answering: at least
// MinOutageSamples lost probes in a row.
type Outage struct {
	Start   time.Time `json:"start"`
	Seconds float64   `json:"seconds"`
	// Cause is "local" when the router stopped answering too (Wi-Fi, cable
	// or the router itself), "isp" when the router kept answering, and
	// "unknown" when the router wasn't measured.
	Cause   string `json:"cause"`
	Ongoing bool   `json:"ongoing,omitempty"` // still down at the last sample
}

// Hour is the internet link at one hour of the day, across all days.
type Hour struct {
	Hour     int     `json:"hour"`
	Samples  int     `json:"samples"`
	LossPct  float64 `json:"loss_pct"`
	MedianMs float64 `json:"median_ms"`
	Outages  int     `json:"outages"`
}

// Day is the internet link on one calendar day. HourMs and HourLoss have 24
// entries; HourMs is -1 for hours with no answered probe, and HourLoss is
// -1 for hours with no data at all.
type Day struct {
	Date     string    `json:"date"` // 2006-01-02, local time
	Samples  int       `json:"samples"`
	LossPct  float64   `json:"loss_pct"`
	MedianMs float64   `json:"median_ms"`
	Outages  int       `json:"outages"`
	HourMs   []float64 `json:"hour_ms"`
	HourLoss []float64 `json:"hour_loss_pct"`
}

// Report is everything Analyze derives from a run of samples.
type Report struct {
	From            time.Time `json:"from"`
	To              time.Time `json:"to"`
	Samples         int       `json:"samples"`
	IntervalSeconds float64   `json:"interval_seconds"`
	Gateway         *Stats    `json:"gateway,omitempty"`
	Internet        *Stats    `json:"internet,omitempty"`
	DNS             *Stats    `json:"dns,omitempty"`
	Outages         []Outage  `json:"outages"`
	OutageSeconds   float64   `json:"outage_seconds"`
	Hours           []Hour    `json:"hours"` // hours of the day that have data
	Days            []Day     `json:"days"`
}

// MinOutageSamples is how many lost internet probes in a row make an
// outage. A single lost probe is packet loss, not an outage.
const MinOutageSamples = 2

// Stats returns the stats for t, or nil if it was never measured.
func (r Report) Stats(t Target) *Stats {
	switch t {
	case Gateway:
		return r.Gateway
	case Internet:
		return r.Internet
	}
	return r.DNS
}

// Analyze summarizes samples (sorted oldest first). Hours and days are in
// loc.
func Analyze(samples []Sample, loc *time.Location) Report {
	r := Report{Outages: []Outage{}, Hours: []Hour{}, Days: []Day{}}
	if len(samples) == 0 {
		return r
	}
	r.From, r.To, r.Samples = samples[0].T, samples[len(samples)-1].T, len(samples)
	interval := typicalInterval(samples)
	r.IntervalSeconds = interval.Seconds()

	r.Gateway = stats(samples, Gateway)
	r.Internet = stats(samples, Internet)
	r.DNS = stats(samples, DNS)

	r.Outages = outages(samples, interval)
	for _, o := range r.Outages {
		r.OutageSeconds += o.Seconds
	}
	r.Hours = hours(samples, r.Outages, loc)
	r.Days = days(samples, r.Outages, loc)
	return r
}

// typicalInterval is the median gap between samples.
func typicalInterval(s []Sample) time.Duration {
	var d []time.Duration
	for i := 1; i < len(s); i++ {
		if g := s[i].T.Sub(s[i-1].T); g > 0 {
			d = append(d, g)
		}
	}
	if len(d) == 0 {
		return 5 * time.Second
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[len(d)/2]
}

// gapAfter is how long a silence between samples must be before it counts
// as "not watching" rather than part of an outage.
func gapAfter(interval time.Duration) time.Duration {
	return max(3*interval, 20*time.Second)
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[len(s)/2]
}

func percentile(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	return s[min(len(s)-1, int(p*float64(len(s))))]
}

func stats(samples []Sample, t Target) *Stats {
	var st Stats
	var ok []float64
	for _, s := range samples {
		v, measured := s.Get(t)
		if !measured {
			continue
		}
		st.Samples++
		if v < 0 {
			st.Lost++
		} else {
			ok = append(ok, v)
		}
	}
	if st.Samples == 0 {
		return nil
	}
	st.LossPct = pct(st.Lost, st.Samples)
	st.MedianMs = median(ok)
	st.P95Ms = percentile(ok, 0.95)
	return &st
}

func outages(samples []Sample, interval time.Duration) []Outage {
	out := []Outage{}
	var run []Sample
	closeRun := func(end time.Time, ongoing bool) {
		if len(run) >= MinOutageSamples {
			out = append(out, Outage{
				Start:   run[0].T,
				Seconds: end.Sub(run[0].T).Seconds(),
				Cause:   cause(run),
				Ongoing: ongoing,
			})
		}
		run = nil
	}
	var prev time.Time
	for _, s := range samples {
		v, measured := s.Get(Internet)
		if !measured {
			continue
		}
		if len(run) > 0 && s.T.Sub(prev) > gapAfter(interval) {
			// We stopped watching mid-outage; count only what we saw.
			closeRun(prev.Add(interval), false)
		}
		prev = s.T
		if v < 0 {
			run = append(run, s)
			continue
		}
		if len(run) > 0 {
			closeRun(s.T, false)
		}
	}
	if len(run) > 0 {
		closeRun(prev.Add(interval), true)
	}
	return out
}

// cause looks at the router during an outage.
func cause(run []Sample) string {
	measured, lost := 0, 0
	for _, s := range run {
		if v, ok := s.Get(Gateway); ok {
			measured++
			if v < 0 {
				lost++
			}
		}
	}
	switch {
	case measured == 0:
		return "unknown"
	case 2*lost > measured:
		return "local"
	}
	return "isp"
}

type bucket struct {
	n, lost int
	ok      []float64
}

func (b *bucket) add(s Sample) {
	v, measured := s.Get(Internet)
	if !measured {
		return
	}
	b.n++
	if v < 0 {
		b.lost++
	} else {
		b.ok = append(b.ok, v)
	}
}

func (b *bucket) loss() float64 {
	if b.n == 0 {
		return -1
	}
	return pct(b.lost, b.n)
}

// pct is a percentage rounded to two decimals, which is plenty for loss.
func pct(part, whole int) float64 {
	return math.Round(10000*float64(part)/float64(whole)) / 100
}

func (b *bucket) med() float64 {
	if len(b.ok) == 0 {
		return -1
	}
	return median(b.ok)
}

func hours(samples []Sample, outs []Outage, loc *time.Location) []Hour {
	var b [24]bucket
	var o [24]int
	for _, s := range samples {
		b[s.T.In(loc).Hour()].add(s)
	}
	for _, x := range outs {
		o[x.Start.In(loc).Hour()]++
	}
	res := []Hour{}
	for h := range b {
		if b[h].n == 0 {
			continue
		}
		res = append(res, Hour{Hour: h, Samples: b[h].n, LossPct: b[h].loss(), MedianMs: max(0, b[h].med()), Outages: o[h]})
	}
	return res
}

func days(samples []Sample, outs []Outage, loc *time.Location) []Day {
	type acc struct {
		all   bucket
		hours [24]bucket
		outs  int
	}
	byDate := map[string]*acc{}
	var order []string
	get := func(t time.Time) *acc {
		k := t.In(loc).Format("2006-01-02")
		a := byDate[k]
		if a == nil {
			a = &acc{}
			byDate[k] = a
			order = append(order, k)
		}
		return a
	}
	for _, s := range samples {
		a := get(s.T)
		a.all.add(s)
		a.hours[s.T.In(loc).Hour()].add(s)
	}
	for _, x := range outs {
		get(x.Start).outs++
	}
	sort.Strings(order)
	res := []Day{}
	for _, k := range order {
		a := byDate[k]
		if a.all.n == 0 {
			continue
		}
		d := Day{Date: k, Samples: a.all.n, LossPct: a.all.loss(), MedianMs: max(0, a.all.med()), Outages: a.outs,
			HourMs: make([]float64, 24), HourLoss: make([]float64, 24)}
		for h := range a.hours {
			d.HourMs[h] = a.hours[h].med()
			d.HourLoss[h] = a.hours[h].loss()
		}
		res = append(res, d)
	}
	return res
}

// Since keeps the samples at or after t.
func Since(samples []Sample, t time.Time) []Sample {
	i := sort.Search(len(samples), func(i int) bool { return !samples[i].T.Before(t) })
	return samples[i:]
}
