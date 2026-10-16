package cli

import (
	"fmt"
	"math"
	"strings"

	"github.com/tworjaga/netcheck/internal/ui"
)

// link is what call-readiness is judged from. Each group of fields has a
// flag (or a zero value) for "not measured", so a judgement is only made on
// what was actually seen.
type link struct {
	PingKnown bool    // LatencyMs and JitterMs were measured
	LatencyMs float64 // idle round trip to the internet
	JitterMs  float64
	LossKnown bool
	LossPct   float64
	DownMbps  float64 // 0: not measured
	UpMbps    float64 // 0: not measured
	LoadedMs  float64 // worst latency while the line is busy; 0: not measured
}

// useVerdict is how well the connection suits one use.
type useVerdict struct {
	Use    string    `json:"use"`
	Status ui.Status `json:"-"`
	Rating string    `json:"rating"` // good, okay, poor, unknown
	Reason string    `json:"reason"`
}

// need is one requirement of a use: a measured value against the level
// where it starts to hurt (warn) and where it breaks (bad).
type need struct {
	known     bool
	value     float64
	warn, bad float64
	higherBad bool // true: bigger values are worse (latency); false: smaller are (bandwidth)
	what      string
	format    func(float64) string
	ideal     string // what good looks like, for the reason
}

func (n need) status() ui.Status {
	if !n.known {
		return ui.Skip
	}
	worse := func(limit float64) bool {
		if n.higherBad {
			return n.value > limit
		}
		return n.value < limit
	}
	switch {
	case worse(n.bad):
		return ui.Bad
	case worse(n.warn):
		return ui.Warn
	}
	return ui.OK
}

// overshoot is how far past the warning level a value is, as a ratio
// (1.0 = right at it), whichever direction is worse.
func (n need) overshoot() float64 {
	if n.higherBad {
		return n.value / n.warn
	}
	if n.value <= 0 {
		return math.Inf(1)
	}
	return n.warn / n.value
}

// msText keeps a decimal below 100 ms, so a value just past a limit never
// rounds onto it ("jitter is 10 ms; games want under 10 ms").
func msText(v float64) string {
	if v < 100 {
		return strings.TrimSuffix(fmt.Sprintf("%.1f", v), ".0") + " ms"
	}
	return fmt.Sprintf("%.0f ms", v)
}

func pctText(v float64) string {
	if v < 10 {
		return fmt.Sprintf("%.1f%%", v)
	}
	return fmt.Sprintf("%.0f%%", v)
}

// judge rates one use from its needs. The reason names the worst problem;
// when everything measured is fine but something wasn't measured, it says so.
func judge(use string, needs []need, okReason string) useVerdict {
	v := useVerdict{Use: use, Status: ui.OK, Rating: "good", Reason: okReason}
	var missing []string
	seen := map[string]bool{}
	measured := 0
	worst, worstOver := ui.OK, 0.0
	for _, n := range needs {
		st := n.status()
		if st == ui.Skip {
			// Bandwidth and loaded latency come from a speed test; say so
			// once rather than once per number it would have given.
			what := n.what
			if what != "packet loss" {
				what = "bandwidth not measured"
			} else {
				what = "packet loss not measured"
			}
			if !seen[what] {
				seen[what] = true
				missing = append(missing, what)
			}
			continue
		}
		measured++
		// The reason names the most serious problem: the worst status, and
		// among equals the one furthest past its limit (221 ms under load
		// against 100 matters more than 10.4 ms jitter against 10).
		over := n.overshoot()
		if st == ui.OK || st < worst || (st == worst && over <= worstOver) {
			continue
		}
		worst, worstOver = st, over
		v.Reason = fmt.Sprintf("%s is %s; %s", n.what, n.format(n.value), n.ideal)
	}
	switch {
	case measured == 0:
		return useVerdict{Use: use, Status: ui.Skip, Rating: "unknown", Reason: "needs a speed test"}
	case worst == ui.Bad:
		v.Status, v.Rating = ui.Bad, "poor"
	case worst == ui.Warn:
		v.Status, v.Rating = ui.Warn, "okay"
	case len(missing) > 0:
		v.Reason += " (" + strings.Join(missing, ", ") + ")"
	}
	return v
}

// readiness rates the connection for video calls, gaming and 4K streaming.
// Thresholds follow common published guidance: Zoom/Teams want about 3 Mbps
// up for HD group calls and under 150 ms latency; competitive games want
// under 60 ms and steady timing; 4K streaming wants about 25 Mbps down.
func readiness(l link) []useVerdict {
	ms := msText
	mbps := fmtMbps
	loaded := need{known: l.LoadedMs > 0, value: l.LoadedMs, higherBad: true, format: ms}

	calls := []need{
		{l.PingKnown, l.LatencyMs, 150, 300, true, "latency", ms, "calls want under 150 ms"},
		{l.PingKnown, l.JitterMs, 30, 50, true, "jitter", ms, "calls want under 30 ms"},
		{l.LossKnown, l.LossPct, 1, 3, true, "packet loss", pctText, "calls break up above 1%"},
		{l.UpMbps > 0, l.UpMbps, 3, 1, false, "upload", mbps, "HD calls want 3 Mbps"},
		{l.DownMbps > 0, l.DownMbps, 3, 1.5, false, "download", mbps, "HD calls want 3 Mbps"},
	}
	loadedCalls := loaded
	loadedCalls.warn, loadedCalls.bad, loadedCalls.what, loadedCalls.ideal = 200, 400, "latency under load", "calls stutter while others download"
	calls = append(calls, loadedCalls)

	gaming := []need{
		{l.PingKnown, l.LatencyMs, 60, 150, true, "latency", ms, "fast-paced games want under 60 ms"},
		{l.PingKnown, l.JitterMs, 10, 30, true, "jitter", ms, "games want under 10 ms"},
		{l.LossKnown, l.LossPct, 0.5, 2, true, "packet loss", pctText, "games rubber-band with any loss"},
		{l.DownMbps > 0, l.DownMbps, 3, 1, false, "download", mbps, "games want 3 Mbps"},
		{l.UpMbps > 0, l.UpMbps, 1, 0.5, false, "upload", mbps, "games want 1 Mbps"},
	}
	loadedGames := loaded
	loadedGames.warn, loadedGames.bad, loadedGames.what, loadedGames.ideal = 100, 250, "latency under load", "games lag while others download"
	gaming = append(gaming, loadedGames)

	stream := []need{
		{l.DownMbps > 0, l.DownMbps, 25, 15, false, "download", mbps, "4K wants 25 Mbps (it drops to HD below 15)"},
		{l.LossKnown, l.LossPct, 2, 5, true, "packet loss", pctText, "streams rebuffer with heavy loss"},
	}
	// Bandwidth is what 4K lives on; without it there is nothing to judge.
	var streamV useVerdict
	if l.DownMbps <= 0 {
		streamV = useVerdict{Use: "4K streaming", Status: ui.Skip, Rating: "unknown", Reason: "needs a speed test"}
	} else {
		streamV = judge("4K streaming", stream, "plenty of bandwidth")
	}

	return []useVerdict{
		judge("Video calls", calls, "steady, low latency"),
		judge("Gaming", gaming, "low latency and steady timing"),
		streamV,
	}
}

// readinessLine sums the uses up in one sentence: what it's good for, and
// the first reason something isn't.
func readinessLine(us []useVerdict) string {
	var good, okay, poor []string
	var why string
	for _, u := range us {
		name := strings.ToLower(u.Use)
		if u.Use == "4K streaming" {
			name = "4K streaming"
		}
		switch u.Status {
		case ui.OK:
			good = append(good, name)
		case ui.Warn:
			okay = append(okay, name)
			if why == "" {
				why = u.Reason
			}
		case ui.Bad:
			poor = append(poor, name)
			if why == "" || len(poor) == 1 {
				why = u.Reason
			}
		}
	}
	var parts []string
	if len(good) > 0 {
		parts = append(parts, "Good for "+joinAnd(good))
	}
	if len(okay) > 0 {
		parts = append(parts, "borderline for "+joinAnd(okay))
	}
	if len(poor) > 0 {
		parts = append(parts, "not good for "+joinAnd(poor))
	}
	if len(parts) == 0 {
		return ""
	}
	s := strings.Join(parts, "; ")
	s = strings.ToUpper(s[:1]) + s[1:]
	if why != "" {
		s += ": " + why
	}
	return s + "."
}

func joinAnd(s []string) string {
	switch len(s) {
	case 0:
		return ""
	case 1:
		return s[0]
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

// readinessRows renders one row per use.
func readinessRows(us []useVerdict) []string {
	labels := map[string]string{"Video calls": "Calls", "Gaming": "Gaming", "4K streaming": "4K video"}
	var out []string
	for _, u := range us {
		row := "  " + ui.Pad(labels[u.Use], 12) + u.Status.Sym() + "  " + ui.Pad(u.Rating, 7)
		out = append(out, ui.Detail(row, ui.Dim(u.Reason), 15))
	}
	return out
}
