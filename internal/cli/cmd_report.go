package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/history"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// reportData is everything a report contains. It's built once and rendered
// as Markdown or JSON.
type reportData struct {
	Generated   time.Time          `json:"generated"`
	Version     string             `json:"netcheck_version"`
	Platform    string             `json:"platform"`
	LocalIP     string             `json:"local_ip,omitempty"`
	Gateway     string             `json:"gateway_ip,omitempty"`
	Public      probe.IPInfo       `json:"public"`
	Verdict     verdict            `json:"verdict"`
	Findings    []verdict          `json:"findings"`
	Checks      doctorReport       `json:"checks"`
	Route       *probe.RouteResult `json:"route,omitempty"`
	History     *history.Report    `json:"history,omitempty"`
	HistoryDays int                `json:"history_days,omitempty"`
	Fast        bool               `json:"fast"`
	Compared    *comparison        `json:"compared,omitempty"`
}

func cell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

func pingSummary(r *probe.PingResult) string {
	if r == nil {
		return "not measured"
	}
	if r.Received == 0 {
		why := "no reply"
		if r.Error != "" {
			why = r.Error
		}
		return fmt.Sprintf("%s (%d probes)", why, r.Sent)
	}
	return fmt.Sprintf("%s average (%s–%s), jitter %s, %.0f%% loss (%d of %d lost)",
		fmtMs(r.AvgMs), fmtMs(r.MinMs), fmtMs(r.MaxMs), fmtMs(r.JitterMs), r.LossPct, r.Sent-r.Received, r.Sent)
}

func methodLabel(m string) string {
	if m == "icmp" {
		return "ICMP ping"
	}
	if strings.HasPrefix(m, "tcp") {
		return "TCP connect (" + m + ")"
	}
	return m
}

// renderMarkdown writes the report for a person: an ISP's support desk, or
// you in a month. Plain-English findings first, numbers after.
func renderMarkdown(r reportData) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	ts := func(t time.Time) string { return t.Format("Mon 2 Jan 2006 15:04 MST") }
	d := r.Checks

	w("# Network report\n\n")
	w("Generated %s by netcheck %s on %s.\n\n", ts(r.Generated), r.Version, r.Platform)

	w("## Summary\n\n**%s**\n\n", r.Verdict.Message)
	bullets := 0
	for _, f := range r.Findings {
		if f.Message != r.Verdict.Message {
			w("- %s\n", f.Message)
			bullets++
		}
	}
	// What watch recorded over days is the strongest evidence a report has.
	if h := r.History; h != nil && h.Samples > 0 {
		if st, msg, _ := historyVerdict(*h, r.Generated.Location()); st != ui.Skip {
			w("- From monitoring with netcheck watch: %s\n", lowerFirst(msg))
			bullets++
		}
	}
	if bullets > 0 {
		w("\n")
	}

	if c := r.Compared; c != nil && len(c.Rows) > 0 {
		w("## Compared with %s\n\n| | Before | After | |\n|---|---|---|---|\n", ts(c.Since))
		for _, row := range c.Rows {
			w("| %s | %s | %s | %s |\n", row.Metric, fmtMetric(row.Before, row.Unit), fmtMetric(row.After, row.Unit), changeWord(row.Change))
		}
		w("\nBefore: %s\n\nNow: %s\n\n", cell(c.BeforeVerdict), cell(r.Verdict.Message))
	}

	w("## Connection\n\n| | |\n|---|---|\n")
	if r.Public.IP != "" {
		w("| Public IP | %s |\n", r.Public.IP)
	}
	if isp := strings.TrimSpace(r.Public.ISP + " " + r.Public.ASN); isp != "" {
		w("| ISP | %s |\n", cell(isp))
	}
	if n := d.NAT; n != nil {
		_, label := natStatus(*n)
		w("| NAT | %s: %s |\n", label, cell(n.Detail))
	}
	if r.LocalIP != "" || r.Gateway != "" {
		w("| This computer / router | %s / %s |\n", orDash(r.LocalIP), orDash(r.Gateway))
	}
	if wf := d.Wifi; wf != nil && wf.Connected {
		w("| Wi-Fi | %s |\n", cell(joinDot(fmt.Sprintf("%d dBm (%s)", wf.SignalDBm, probe.SignalQuality(wf.SignalDBm)), wf.Band, chanLabel(wf.Channel), wf.Radio, crowdLabel(wf.Crowding))))
	} else if wf != nil {
		w("| Wi-Fi | not in use (wired, or no adapter) |\n")
	}
	w("\n")

	w("## Measurements\n\n| Check | Result | How |\n|---|---|---|\n")
	if d.Gateway != nil {
		w("| Router %s | %s | %s |\n", r.Gateway, pingSummary(d.Gateway), methodLabel(d.Gateway.Method))
	}
	if d.Internet != nil {
		w("| Internet %s | %s | %s |\n", d.Internet.Addr, pingSummary(d.Internet), methodLabel(d.Internet.Method))
	}
	for i, x := range d.DNS {
		label := "DNS " + strings.TrimSpace(x.Label+" "+x.Addr)
		if i > 0 {
			label = "DNS " + x.Label + " (for comparison)"
		}
		res := fmt.Sprintf("%s median, %d of %d answered", fmtMs(x.MedianMs), x.Answered, x.Lookups)
		if x.Answered == 0 {
			res = "no answers: " + x.Error
		}
		if x.RewritesNX {
			res += ", rewrites unknown names"
		}
		w("| %s | %s | lookups of %d names |\n", cell(label), cell(res), x.Lookups)
	}
	if s := d.Speed; s != nil {
		if s.Error != "" {
			w("| Speed | not measured: %s | |\n", cell(s.Error))
		} else {
			lat := "latency " + fmtMs(s.IdleMs) + " idle"
			if s.DownLoadedMs > 0 {
				lat += ", " + fmtMs(s.DownLoadedMs) + " while downloading"
			}
			if s.UpLoadedMs > 0 {
				lat += ", " + fmtMs(s.UpLoadedMs) + " while uploading"
			}
			if s.Grade != "" {
				lat += " (bufferbloat grade " + s.Grade + ")"
			}
			w("| Speed | %s down, %s up; %s | %s, %s per direction |\n", fmtMbps(s.DownMbps), fmtMbps(s.UpMbps), lat, orDash(s.Server), fmtDur(doctorSpeedTime))
		}
	}
	if v := d.IPv6; v != nil {
		_, msg := ipv6Verdict(*v)
		w("| IPv6 | %s | TCP connect to an IPv6-only host |\n", cell(msg))
	}
	w("\n")

	if len(d.Readiness) > 0 && r.Verdict.Status != "bad" {
		w("## Good for\n\n")
		for _, u := range d.Readiness {
			w("- **%s:** %s. %s\n", u.Use, u.Rating, upperFirst(u.Reason)+".")
		}
		w("\n")
	}

	if rt := r.Route; rt != nil && len(rt.Hops) > 0 {
		w("## Route to %s\n\n| Hop | Address | Loss | Average | Worst |\n|---|---|---|---|---|\n", rt.Addr)
		for _, h := range rt.Hops {
			if h.IP == "" || h.Received == 0 {
				w("| %d | (no reply) | | | |\n", h.TTL)
				continue
			}
			w("| %d | %s | %.0f%% | %s | %s |\n", h.TTL, h.IP, h.LossPct, fmtMs(h.AvgMs), fmtMs(h.WorstMs))
		}
		w("\nA hop that shows loss while the hops after it don't is just a router that deprioritizes replies to probes, not a fault.\n\n")
	}

	if h := r.History; h != nil && h.Samples > 0 {
		in := h.Internet
		w("## History (last %d days)\n\n", r.HistoryDays)
		w("Recorded by `netcheck watch` from %s to %s, %s about every %s.\n\n", ts(h.From), ts(h.To), plural(h.Samples, "sample", "samples"), fmtDur(time.Duration(h.IntervalSeconds*float64(time.Second))))
		if in != nil {
			w("- Internet: %.2f%% of probes lost, median latency %s, 95th percentile %s.\n", in.LossPct, fmtMs(in.MedianMs), fmtMs(in.P95Ms))
		}
		if g := h.Gateway; g != nil {
			w("- Router: %.2f%% of probes lost, median latency %s.\n", g.LossPct, fmtMs(g.MedianMs))
		}
		w("- Outages (2 or more lost probes in a row): %d, %s in total.\n", len(h.Outages), fmtDur(time.Duration(h.OutageSeconds*float64(time.Second))))
		if bad := badHours(*h); len(bad) > 0 {
			var parts []string
			for _, x := range bad[:min(3, len(bad))] {
				parts = append(parts, fmt.Sprintf("%s (%s, %.1f%% loss)", hourName(x.Hour), fmtMs(x.MedianMs), x.LossPct))
			}
			w("- Worst hours of the day: %s.\n", strings.Join(parts, ", "))
		}
		if len(h.Outages) > 0 {
			w("\n| Outage started | Duration | Router during the outage |\n|---|---|---|\n")
			causes := map[string]string{"local": "also unreachable", "isp": "answering normally", "unknown": "not measured"}
			for _, o := range h.Outages[max(0, len(h.Outages)-20):] {
				dur := fmtDur(time.Duration(o.Seconds * float64(time.Second)))
				if o.Ongoing {
					dur += " (still down at the last sample)"
				}
				w("| %s | %s | %s |\n", ts(o.Start), dur, causes[o.Cause])
			}
		}
		w("\n")
	}

	w("## How this was measured\n\n")
	w("- Latency and loss: 10 probes 150 ms apart to the router and to 1.1.1.1 (8.8.8.8 as a fallback), by ICMP ping where the system allows it, otherwise by timing TCP connections.\n")
	w("- DNS: the system's resolver compared with Cloudflare, Google and Quad9, looking up the same names.\n")
	if d.Speed != nil {
		w("- Speed: parallel downloads and uploads against speed.cloudflare.com; bufferbloat is how much latency rises while the line is busy.\n")
	}
	if r.Route != nil && len(r.Route.Hops) > 0 {
		w("- Route: ICMP probes with rising TTL (or the system's tracert/traceroute), several rounds per hop.\n")
	}
	w("\nThis report contains your public IP address. It doesn't contain passwords, Wi-Fi names or a list of your devices.\n")
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}

func crowdLabel(c string) string {
	if c == "" {
		return ""
	}
	return c + " channel"
}

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	format := fs.String("format", "md", "md or json")
	out := fs.String("o", "", "write to this file instead of the screen")
	fast := fs.Bool("fast", false, "skip the speed test and the route")
	days := fs.Int("days", 7, "how much watch history to include")
	asJSON := fs.Bool("json", false, "same as --format json")
	compareWith := fs.String("compare", "", "compare with an earlier report: \"last\", or a file from --format json")
	parseInterspersed(fs, args)
	if *asJSON {
		*format = "json"
	}
	if *format != "md" && *format != "json" {
		fmt.Fprintf(os.Stderr, "netcheck: --format must be md or json, not %q\n", *format)
		return 2
	}
	var before *reportData
	if *compareWith != "" {
		b, err := loadReport(*compareWith)
		if err != nil {
			fmt.Fprintln(os.Stderr, "netcheck: can't compare: "+err.Error())
			return 2
		}
		before = &b
	}
	toScreen := *out == ""
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if !toScreen {
		ui.Title("report")
	}
	r := reportData{Generated: time.Now(), Version: version, Platform: runtime.GOOS + "/" + runtime.GOARCH, Fast: *fast, HistoryDays: *days}
	t := ui.Begin("Measuring")
	what := "router, internet, DNS, Wi-Fi, IPv6, NAT, speed…"
	if *fast {
		what = "router, internet, DNS, Wi-Fi, IPv6, NAT…"
	}
	t.Progress(what)
	g := ui.NewSilentGroup()
	d, notes := runChecks(ctx, *fast, g)
	g.End()
	if ip := probe.LocalIP(); ip != nil {
		r.LocalIP = ip.String()
	}
	if gw, err := probe.DefaultGateway(); err == nil {
		r.Gateway = gw.String()
	}
	if d.online() && ctx.Err() == nil {
		t.Progress("looking up your ISP…")
		if d.NAT != nil && d.NAT.Public != "" {
			r.Public = probe.LookupASN(ctx, parseIP(d.NAT.Public))
		} else {
			r.Public = probe.GetIPInfo(ctx)
		}
		if !*fast {
			t.Progress("tracing the route to 1.1.1.1…")
			rt := probe.Trace(ctx, "1.1.1.1", probe.RouteOpts{MaxHops: 20, Rounds: 5, Interval: 300 * time.Millisecond})
			r.Route = &rt
		}
	}
	t.Clear()
	if ctx.Err() != nil {
		ui.Println("  " + ui.Dim("Interrupted; no report written.") + "\n")
		return 130
	}

	if path, err := history.DefaultPath(); err == nil {
		if read, err := history.Read(path); err == nil && len(read.Samples) > 0 {
			ss := history.Since(read.Samples, r.Generated.Add(-time.Duration(max(*days, 1))*24*time.Hour))
			if len(ss) > 0 {
				h := history.Analyze(ss, time.Local)
				r.History = &h
			}
		}
	}

	st, head, findings := doctorVerdict(d)
	r.Verdict, r.Findings = verdict{st.String(), head}, findingsJSON(findings)
	r.Checks = doctorReport{
		Gateway: d.Gateway, Internet: d.Internet, DNS: d.DNS, Readiness: d.Readiness,
		Verdict: r.Verdict, Findings: r.Findings,
		Wifi: redactWifi(d.Wifi), IPv6: d.IPv6, NAT: d.NAT, Speed: d.Speed, Fast: *fast, Notes: notes,
	}

	if before != nil {
		c := compareReports(*before, r)
		r.Compared = &c
	}
	// Kept for the next `report --compare last`; failing to keep it only
	// costs that comparison.
	_ = saveLastReport(r)

	var body []byte
	if *format == "json" {
		body, _ = json.MarshalIndent(r, "", "  ")
		body = append(body, '\n')
	} else {
		body = []byte(renderMarkdown(r))
	}
	if toScreen {
		os.Stdout.Write(body)
		return 0
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		ui.Println("  " + ui.Alert("Couldn't write the report: "+err.Error()) + "\n")
		return 1
	}
	ui.Println("  " + st.Paint(head))
	if r.Compared != nil && len(r.Compared.Rows) > 0 {
		ui.Println("  " + ui.Dim(compareSummary(*r.Compared)))
	}
	ui.Println("  " + ui.Dim("Report saved to "+*out+". It includes your public IP address, so share it only with your ISP or someone helping you.") + "\n")
	return 0
}

// redactWifi drops what an ISP doesn't need: network names and neighbours.
func redactWifi(w *probe.WifiInfo) *probe.WifiInfo {
	if w == nil {
		return nil
	}
	c := *w
	c.SSID, c.BSSID, c.Neighbors = "", "", nil
	return &c
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
