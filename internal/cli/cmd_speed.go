package cli

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

func fmtMbps(v float64) string {
	switch {
	case v >= 10000:
		return fmt.Sprintf("%.1f Gbps", v/1000)
	case v >= 100:
		return fmt.Sprintf("%.0f Mbps", v)
	case v >= 1:
		return fmt.Sprintf("%.1f Mbps", v)
	}
	return fmt.Sprintf("%.2f Mbps", v)
}

// speedVerdict explains a speed result in plain English.
func speedVerdict(r probe.SpeedResult) (ui.Status, string) {
	switch {
	case r.Error != "":
		return ui.Skip, "The speed test couldn't run: " + r.Error + "."
	case r.Grade == "F" || r.Grade == "D":
		return ui.Warn, fmt.Sprintf("Your connection stalls when it's busy: latency jumps by %.0f ms under load (grade %s). Calls and games will stutter while anyone downloads or uploads. Turning on SQM or a \"smart queue\" in your router fixes this.", r.BloatMs, r.Grade)
	case r.DownMbps > 0 && r.DownMbps < 5:
		return ui.Warn, fmt.Sprintf("Download speed is low (%s). Streaming and large downloads will feel slow.", fmtMbps(r.DownMbps))
	case r.UpMbps > 0 && r.UpMbps < 1:
		return ui.Warn, fmt.Sprintf("Upload speed is very low (%s), which hurts video calls and cloud backups.", fmtMbps(r.UpMbps))
	case r.Grade == "C":
		return ui.Warn, fmt.Sprintf("Latency rises by %.0f ms when the connection is busy (grade C). You may notice lag in calls while others download.", r.BloatMs)
	case r.Partial != "":
		return ui.Warn, "Part of the speed test failed (" + r.Partial + ")."
	}
	return ui.OK, fmt.Sprintf("Speed is good (%s down, %s up) and stays responsive under load.", fmtMbps(r.DownMbps), fmtMbps(r.UpMbps))
}

// sqmSettings are shaper limits to type into the router's SQM / smart queue
// page: 90% of what was measured, so the queue builds in the router (where
// SQM manages it) instead of in the modem.
type sqmSettings struct {
	DownMbps float64 `json:"down_mbps"`
	UpMbps   float64 `json:"up_mbps"`
}

// sqmAdvice suggests SQM limits when latency rises noticeably under load.
func sqmAdvice(r probe.SpeedResult) *sqmSettings {
	if r.Error != "" || r.DownMbps <= 0 || r.UpMbps <= 0 || (r.Grade != "C" && r.Grade != "D" && r.Grade != "F") {
		return nil
	}
	return &sqmSettings{DownMbps: roundMbps(r.DownMbps * 0.9), UpMbps: roundMbps(r.UpMbps * 0.9)}
}

// roundMbps rounds down to a precision a router page accepts.
func roundMbps(v float64) float64 {
	if v >= 10 {
		return math.Floor(v)
	}
	return math.Floor(v*10) / 10
}

func (s sqmSettings) line() string {
	return fmt.Sprintf("SQM settings to try: download %s (%.0f kbit/s), upload %s (%.0f kbit/s). Then run netcheck speed again.",
		fmtMbps(s.DownMbps), s.DownMbps*1000, fmtMbps(s.UpMbps), s.UpMbps*1000)
}

// speedLink is what a speed test knows about the link. It doesn't measure
// packet loss.
func speedLink(r probe.SpeedResult) link {
	return link{
		PingKnown: r.IdleMs > 0, LatencyMs: r.IdleMs, JitterMs: r.IdleJitterMs,
		DownMbps: r.DownMbps, UpMbps: r.UpMbps, LoadedMs: max(r.DownLoadedMs, r.UpLoadedMs),
	}
}

// runSpeed runs the test and prints spinner rows that resolve into results.
func runSpeed(ctx context.Context, cfg probe.SpeedConfig) probe.SpeedResult {
	tasks := map[string]*ui.Task{}
	labels := map[string]string{"latency": "Latency", "download": "Download", "upload": "Upload"}
	var spark, lats []float64
	top := 0.0 // gauge scale: a round number above the fastest reading so far
	begin := func(phase string) *ui.Task {
		if t, ok := tasks[phase]; ok {
			return t
		}
		t := ui.Begin(labels[phase])
		tasks[phase] = t
		spark, lats, top = nil, nil, 0
		return t
	}
	res := probe.RunSpeed(ctx, cfg, func(p probe.SpeedProgress) {
		t := begin(p.Phase)
		switch {
		case p.Phase == "latency" && !p.Done:
			t.Progress(fmtMs(p.LatencyMs))
		case p.Phase == "latency":
			t.Finish(ui.Row("Latency", ui.OK, "idle", fmtMs(p.LatencyMs), ui.Dim(p.Server)))
		case !p.Done:
			spark = append(spark, p.Mbps)
			lat := ""
			if p.LatencyMs > 0 {
				lats = append(lats, p.LatencyMs)
				lat = ui.Dim("  latency "+fmtMs(p.LatencyMs)+" ") + ui.Spark(tail(lats, 8))
			}
			if !ui.Framed() {
				t.Progress(fmt.Sprintf("%-10s", fmtMbps(p.Mbps)) + ui.Trend(tail(spark, 24)) + lat)
				break
			}
			// A live gauge: how full the line is, on a round scale that
			// grows with the fastest reading, and latency climbing beside
			// it as the line fills (bufferbloat, live).
			top = max(top, ui.NiceCeil(p.Mbps*1.1))
			t.Progress(fmt.Sprintf("%-10s", fmtMbps(p.Mbps)) + ui.Gauge(p.Mbps/top, 14) + lat)
		default:
			st := ui.OK
			if p.Mbps <= 0 {
				st = ui.Bad
			}
			extra := ui.Trend(tail(spark, 24))
			if p.LatencyMs > 0 {
				extra += ui.Dim(fmt.Sprintf("  latency %s", fmtMs(p.LatencyMs)))
			}
			t.Finish(ui.Row(labels[p.Phase], st, fmtMbps(p.Mbps), "", extra))
		}
	})
	if res.Error != "" && len(tasks) == 0 {
		ui.Println(ui.Row("Latency", ui.Bad, "unreachable", "–", ui.Dim("speed.cloudflare.com")))
	}
	// Phases that never resolved (error or Ctrl-C): clear their spinners.
	for phase, t := range tasks {
		if phase == "latency" && res.IdleMs > 0 {
			continue
		}
		if (phase == "download" && res.DownMbps > 0) || (phase == "upload" && res.UpMbps > 0) {
			continue
		}
		t.Finish(ui.Row(labels[phase], ui.Skip, "–", "", ui.Dim("not completed")))
	}
	return res
}

func cmdSpeed(args []string) int {
	fs := flag.NewFlagSet("speed", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	dur := fs.Duration("t", 8*time.Second, "test length per direction")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cfg := probe.DefaultSpeedConfig()
	cfg.Duration = max(*dur, 2*time.Second)
	cfg.Warmup = min(cfg.Warmup, cfg.Duration/3)

	ui.Title("speed")
	ui.Open("Speed")
	res := runSpeed(ctx, cfg)
	if ctx.Err() != nil {
		ui.Close()
		ui.Println("\n  " + ui.Dim("Interrupted."))
		return 130
	}
	if res.Grade != "" {
		st := ui.OK
		if res.Grade >= "C" {
			st = ui.Warn
		}
		ui.Println(ui.Row("Bufferbloat", st, "grade "+res.Grade, "", ui.Dim(fmt.Sprintf("+%.0f ms under load", res.BloatMs))))
	}
	ui.Close()
	var ready []useVerdict
	if res.Error == "" {
		ready = readiness(speedLink(res))
		ui.Println("")
		ui.Open("Good for")
		for _, row := range readinessRows(ready) {
			ui.Println(row)
		}
		ui.Close()
	}
	st, msg := speedVerdict(res)
	var notes []string
	sqm := sqmAdvice(res)
	if sqm != nil {
		notes = append(notes, sqm.line())
	}
	if line := readinessLine(ready); line != "" {
		notes = append(notes, line)
	}
	ui.Verdict(st, msg, notes...)
	ui.Println("")
	if *asJSON {
		printJSON(struct {
			probe.SpeedResult
			Readiness []useVerdict `json:"readiness,omitempty"`
			SQM       *sqmSettings `json:"sqm,omitempty"`
		}{res, ready, sqm})
	}
	if res.Error != "" {
		return 1
	}
	return 0
}
