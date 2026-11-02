package cli

import (
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/history"
	"github.com/tworjaga/netcheck/internal/ui"
)

// minHourSamples is how many samples an hour of the day needs before it
// can be called out as better or worse than the rest.
const minHourSamples = 20

// hourName says an hour of the day the way people do: "8pm", "midnight".
func hourName(h int) string {
	switch {
	case h == 0:
		return "midnight"
	case h == 12:
		return "noon"
	case h < 12:
		return fmt.Sprintf("%dam", h)
	}
	return fmt.Sprintf("%dpm", h-12)
}

// badHours are the hours of the day that are clearly worse than the
// overall link: more loss or much slower. Worst first.
func badHours(r history.Report) []history.Hour {
	in := r.Internet
	if in == nil {
		return nil
	}
	var qual, bad []history.Hour
	for _, h := range r.Hours {
		if h.Samples >= minHourSamples {
			qual = append(qual, h)
		}
	}
	if len(qual) < 4 { // too little of the day to compare
		return nil
	}
	for _, h := range qual {
		lossy := h.LossPct >= 1 && h.LossPct >= 2*in.LossPct
		slow := h.MedianMs >= 1.5*in.MedianMs && h.MedianMs-in.MedianMs >= 10
		if lossy || slow {
			bad = append(bad, h)
		}
	}
	sort.SliceStable(bad, func(i, j int) bool {
		if bad[i].LossPct != bad[j].LossPct {
			return bad[i].LossPct > bad[j].LossPct
		}
		return bad[i].MedianMs > bad[j].MedianMs
	})
	return bad
}

// outageCluster finds the hour most outages start in (counting the hour
// after it too), if at least half of them, and three or more, do.
func outageCluster(r history.Report, loc *time.Location) (int, bool) {
	if len(r.Outages) < 3 {
		return 0, false
	}
	var by [24]int
	for _, o := range r.Outages {
		by[o.Start.In(loc).Hour()]++
	}
	best, bestN := 0, 0
	for h := range by {
		if n := by[h] + by[(h+1)%24]; n > bestN {
			best, bestN = h, n
		}
	}
	if by[best] == 0 {
		best = (best + 1) % 24
	}
	return best, 2*bestN >= len(r.Outages)
}

// historyVerdict turns a report into plain-English findings. loc is used to
// name the hour outages cluster around.
func historyVerdict(r history.Report, loc *time.Location) (ui.Status, string, []finding) {
	in := r.Internet
	if r.Samples == 0 || in == nil || in.Samples == 0 {
		return ui.Skip, "No history yet. Run netcheck watch to start recording.", nil
	}
	span := fmtDur(r.To.Sub(r.From))
	if len(r.Days) > 1 {
		span = plural(len(r.Days), "day", "days")
	}
	var fs []finding
	if n := len(r.Outages); n > 0 {
		total := time.Duration(r.OutageSeconds * float64(time.Second))
		st := ui.Warn
		if n >= 3 || total >= 5*time.Minute {
			st = ui.Bad
		}
		msg := fmt.Sprintf("The internet dropped out %s over %s, %s in total.", times(n), span, fmtDur(total))
		switch outageCause(r.Outages) {
		case "local":
			msg += " Your router stopped answering too, so it's the Wi-Fi, cable or router."
		case "isp":
			msg += " Your router kept answering, which points to your ISP."
		}
		if h, ok := outageCluster(r, loc); ok {
			msg += " It drops around " + hourName(h) + "."
		}
		fs = append(fs, finding{st, msg})
	}
	if in.LossPct > 2 {
		fs = append(fs, finding{ui.Warn, fmt.Sprintf("%.1f%% of probes to the internet were lost over %s.", in.LossPct, span)})
	}
	if bad := badHours(r); len(bad) > 0 {
		h := bad[0]
		var msg string
		if h.LossPct >= 1 && h.LossPct >= 2*in.LossPct {
			msg = fmt.Sprintf("It gets unreliable around %s: %.1f%% loss then, against %.1f%% overall.", hourName(h.Hour), h.LossPct, in.LossPct)
			if h.MedianMs >= 1.5*in.MedianMs && h.MedianMs-in.MedianMs >= 10 {
				msg += fmt.Sprintf(" Latency rises too (%s against %s).", fmtMs(h.MedianMs), fmtMs(in.MedianMs))
			}
		} else {
			msg = fmt.Sprintf("It slows down around %s: %s then, against %s usually.", hourName(h.Hour), fmtMs(h.MedianMs), fmtMs(in.MedianMs))
			if h.Hour >= 17 && h.Hour <= 23 {
				msg += " That's typical of a congested ISP at peak time."
			}
		}
		fs = append(fs, finding{ui.Warn, msg})
	}
	if gw := r.Gateway; gw != nil && gw.LossPct > 2 {
		fs = append(fs, finding{ui.Warn, fmt.Sprintf("Packet loss to your router (%.1f%%), usually weak Wi-Fi or interference.", gw.LossPct)})
	}
	if d := r.DNS; d != nil && d.LossPct > 5 {
		fs = append(fs, finding{ui.Warn, fmt.Sprintf("Your DNS server missed %.0f%% of lookups.", d.LossPct)})
	}
	st, head := lead(fs, fmt.Sprintf("Stable over %s: no outages, and no time of day stands out.", span))
	return st, head, fs
}

// dayStrip renders 24 hourly cells: a bar for the median latency, × for an
// hour that was mostly lost, and a dim dot for an hour with no data.
func dayStrip(d history.Day, lo, hi float64) string {
	var b strings.Builder
	for h := 0; h < 24; h++ {
		switch {
		case d.HourLoss[h] < 0:
			b.WriteString(ui.Gap())
		case d.HourMs[h] < 0 || d.HourLoss[h] >= 50:
			b.WriteString(ui.Bars([]float64{-1}, lo, hi, -1))
		default:
			b.WriteString(ui.LatencyBars([]float64{d.HourMs[h]}, lo, hi, -1))
		}
	}
	return b.String()
}

// stripScale is shared by every day so their bars compare.
func stripScale(days []history.Day) (lo, hi float64) {
	lo, hi = -1, 0
	for _, d := range days {
		for _, v := range d.HourMs {
			if v < 0 {
				continue
			}
			if lo < 0 || v < lo {
				lo = v
			}
			hi = max(hi, v)
		}
	}
	lo = max(lo, 0)
	return lo, max(hi, lo*1.5, lo+2)
}

func cmdHistory(args []string) int {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	days := fs.Int("days", 7, "how many days back to look")
	logPath := fs.String("log", "", "history log path (default: config dir, or $NETCHECK_HISTORY)")
	asJSON := fs.Bool("json", false, "machine-readable output")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)

	ui.Title("history")
	path := *logPath
	if path == "" {
		var err error
		if path, err = history.DefaultPath(); err != nil {
			ui.Println("  " + ui.Alert("Can't find the history log: "+err.Error()) + "\n")
			return 1
		}
	}
	read, err := history.Read(path)
	if err != nil {
		ui.Println("  " + ui.Alert("Can't read "+path+": "+err.Error()) + "\n")
		if *asJSON {
			printJSON(map[string]string{"path": path, "error": err.Error()})
		}
		return 1
	}
	loc := time.Local
	samples := history.Since(read.Samples, time.Now().Add(-time.Duration(max(*days, 1))*24*time.Hour))
	rep := history.Analyze(samples, loc)
	st, head, findings := historyVerdict(rep, loc)

	if *asJSON {
		printJSON(struct {
			Path     string         `json:"path"`
			Skipped  int            `json:"skipped_lines"`
			Report   history.Report `json:"report"`
			Verdict  verdict        `json:"verdict"`
			Findings []verdict      `json:"findings"`
		}{path, read.Skipped, rep, verdict{st.String(), head}, findingsJSON(findings)})
		return 0
	}
	if rep.Samples == 0 {
		ui.Println("  " + st.Paint(head))
		if len(read.Samples) > 0 {
			ui.Println("  " + ui.Dim(fmt.Sprintf("Nothing in the last %s; the log goes back to %s.", plural(*days, "day", "days"), read.Samples[0].T.In(loc).Format("Jan 2"))))
		}
		ui.Println("")
		return 0
	}

	span := rep.From.In(loc).Format("Mon Jan 2 15:04") + " – " + rep.To.In(loc).Format("Mon Jan 2 15:04") + " · " + plural(rep.Samples, "sample", "samples")
	if ui.Framed() {
		ui.Open(span)
	} else {
		ui.Println("  " + ui.Dim(span) + "\n")
	}
	labels := map[history.Target]string{history.Gateway: "Gateway", history.Internet: "Internet", history.DNS: "DNS"}
	for _, t := range history.Targets {
		s := rep.Stats(t)
		if s == nil {
			continue
		}
		rst := ui.OK
		if s.LossPct > 2 {
			rst = ui.Warn
		}
		extra := ""
		if t == history.Internet && len(rep.Outages) > 0 {
			extra = ui.Dim(plural(len(rep.Outages), "outage", "outages") + ", " + fmtDur(time.Duration(rep.OutageSeconds*float64(time.Second))))
			rst = max(rst, ui.Warn)
		}
		ui.Println(ui.Row(labels[t], rst, fmt.Sprintf("%.1f%% loss", s.LossPct), fmtMs(s.MedianMs), extra))
	}

	// One strip per day: the internet's median latency hour by hour.
	ui.Close()
	ui.Println("")
	ui.Open("Internet latency by hour")
	lo, hi := stripScale(rep.Days)
	for _, d := range rep.Days {
		day, _ := time.ParseInLocation("2006-01-02", d.Date, loc)
		extra := fmtMs(d.MedianMs) + "  " + fmt.Sprintf("%.1f%% loss", d.LossPct)
		if d.Outages > 0 {
			extra += " · " + plural(d.Outages, "outage", "outages")
		}
		ui.Println("  " + ui.Pad(day.Format("Mon Jan 2"), 12) + dayStrip(d, lo, hi) + "  " + ui.Dim(extra))
	}
	ui.Println("  " + strings.Repeat(" ", 12) + ui.Dim("0     6     12    18    "))

	if bad := badHours(rep); len(bad) > 0 {
		var parts []string
		for _, h := range bad[:min(3, len(bad))] {
			parts = append(parts, fmt.Sprintf("%s (%s, %.1f%% loss)", hourName(h.Hour), fmtMs(h.MedianMs), h.LossPct))
		}
		ui.Println("\n  " + ui.Dim(ui.Pad("Worst hours", 12)) + strings.Join(parts, ui.Dim(" · ")))
	}
	if n := len(rep.Outages); n > 0 {
		ui.Println("\n  " + ui.Dim("Outages"))
		causes := map[string]string{"local": "router unreachable too", "isp": "router fine: beyond it", "unknown": ""}
		for _, o := range rep.Outages[max(0, n-5):] {
			note := causes[o.Cause]
			if o.Ongoing {
				note = strings.TrimPrefix(note+" · still down at the last sample", " · ")
			}
			ui.Println("  " + ui.Pad(o.Start.In(loc).Format("Mon Jan 2 15:04"), 18) + ui.Pad(fmtDur(time.Duration(o.Seconds*float64(time.Second))), 10) + ui.Dim(note))
		}
		if n > 5 {
			ui.Println("  " + ui.Dim(fmt.Sprintf("and %d earlier", n-5)))
		}
	}

	printVerdict(st, head, findings)
	if read.Skipped > 0 {
		verb := "were"
		if read.Skipped == 1 {
			verb = "was"
		}
		ui.Println("  " + ui.Dim(plural(read.Skipped, "line", "lines")+" in the log couldn't be read (damaged, or from a newer netcheck) and "+verb+" skipped."))
	}
	ui.Println("")
	return 0
}

func findingsJSON(fs []finding) []verdict {
	out := []verdict{}
	for _, f := range fs {
		out = append(out, verdict{f.St.String(), f.Msg})
	}
	return out
}
