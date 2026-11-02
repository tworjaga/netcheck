package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/history"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// clock is the watcher's sense of time, swapped for a fake in tests.
type clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration)
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) Sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// watchTarget is one link being watched.
type watchTarget struct {
	t     history.Target
	label string // row label
	addr  string // what is probed, for display
	probe func(ctx context.Context, timeout time.Duration) float64
}

// watcher probes every target once per interval, in parallel, and hands
// each tick to record as one sample.
type watcher struct {
	clock    clock
	interval time.Duration
	until    time.Duration // 0: until ctx is cancelled
	targets  []watchTarget
	record   func(history.Sample)
}

// probeTimeout keeps one tick's probes shorter than the interval.
func probeTimeout(interval time.Duration) time.Duration {
	return min(2*time.Second, interval*4/5)
}

func (w watcher) run(ctx context.Context) []history.Sample {
	var all []history.Sample
	start := w.clock.Now()
	timeout := probeTimeout(w.interval)
	for ctx.Err() == nil {
		tick := w.clock.Now()
		vals := make([]float64, len(w.targets))
		var wg sync.WaitGroup
		for i, t := range w.targets {
			wg.Add(1)
			go func() {
				defer wg.Done()
				vals[i] = t.probe(ctx, timeout)
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			break // interrupted mid-tick: a cut-off probe isn't a lost one
		}
		// Whole seconds keep log lines short; the interval is at least 1 s.
		s := history.Sample{V: history.Version, T: tick.Truncate(time.Second)}
		for i, t := range w.targets {
			v := history.Ms(vals[i])
			switch t.t {
			case history.Gateway:
				s.GW = v
			case history.Internet:
				s.Net = v
			case history.DNS:
				s.DNS = v
			}
		}
		all = append(all, s)
		if w.record != nil {
			w.record(s)
		}
		if w.until > 0 && w.clock.Now().Sub(start)+w.interval >= w.until {
			break
		}
		w.clock.Sleep(ctx, tick.Add(w.interval).Sub(w.clock.Now()))
	}
	return all
}

// watchVerdict judges a watch session. It returns the headline status and
// message plus every finding, most serious first in the headline.
func watchVerdict(r history.Report, watched time.Duration) (ui.Status, string, []finding) {
	in := r.Internet
	if in == nil || in.Samples == 0 {
		return ui.Skip, "Nothing was measured.", nil
	}
	var fs []finding
	if in.Lost == in.Samples {
		msg := "The internet never answered while watching."
		if gw := r.Gateway; gw != nil && gw.Lost < gw.Samples {
			msg += " Your router did, so the problem is beyond it: the router's uplink or your ISP."
		}
		return ui.Bad, msg, []finding{{ui.Bad, msg}}
	}
	if n := len(r.Outages); n > 0 {
		st := ui.Warn
		total := time.Duration(r.OutageSeconds * float64(time.Second))
		if total >= 5*time.Minute || (watched > 0 && total*20 >= watched) {
			st = ui.Bad
		}
		msg := fmt.Sprintf("The internet dropped out %s, %s in total.", times(n), fmtDur(total))
		switch outageCause(r.Outages) {
		case "local":
			msg += " Your router stopped answering too, so look at the Wi-Fi, cable or router first."
		case "isp":
			msg += " Your router kept answering, which points to your ISP or the router's uplink."
		}
		fs = append(fs, finding{st, msg})
	}
	if in.LossPct > 2 {
		fs = append(fs, finding{ui.Warn, fmt.Sprintf("%.1f%% of probes to the internet were lost. Calls and games notice anything above 1%%.", in.LossPct)})
	}
	if gw := r.Gateway; gw != nil && gw.Samples > 0 && gw.LossPct > 2 {
		fs = append(fs, finding{ui.Warn, fmt.Sprintf("Packet loss to your router (%.1f%%). That usually means weak Wi-Fi or interference.", gw.LossPct)})
	}
	if d := r.DNS; d != nil && d.Samples > 0 && d.LossPct > 5 {
		fs = append(fs, finding{ui.Warn, fmt.Sprintf("Your DNS server missed %.0f%% of lookups, which feels like pages that hang before loading.", d.LossPct)})
	}
	if in.P95Ms > 3*in.MedianMs && in.P95Ms-in.MedianMs > 50 {
		fs = append(fs, finding{ui.Warn, fmt.Sprintf("Latency spikes now and then (%s at worst vs %s usually), which shows up as stutter in calls.", fmtMs(in.P95Ms), fmtMs(in.MedianMs))})
	}
	st, head := lead(fs, "Stable the whole time: no drops and steady latency.")
	return st, head, fs
}

// outageCause is the cause shared by most outages ("" if mixed).
func outageCause(outs []history.Outage) string {
	n := map[string]int{}
	for _, o := range outs {
		n[o.Cause]++
	}
	for c, k := range n {
		if 2*k > len(outs) && c != "unknown" {
			return c
		}
	}
	return ""
}

func times(n int) string {
	switch n {
	case 1:
		return "once"
	case 2:
		return "twice"
	}
	return fmt.Sprintf("%d times", n)
}

// liveLines renders the watch display: one row per target with a scrolling
// sparkline of its most recent samples.
func liveLines(targets []watchTarget, recent [][]float64, n int, elapsed time.Duration, drops int, every time.Duration) []string {
	var lines []string
	for i, t := range targets {
		r := recent[i]
		st, metric := ui.OK, "–"
		if len(r) > 0 {
			last := r[len(r)-1]
			lost := 0
			for _, v := range r {
				if v < 0 {
					lost++
				}
			}
			switch {
			case last < 0:
				st, metric = ui.Bad, "lost"
			case lost > 0:
				st, metric = ui.Warn, fmtMs(last)
			default:
				metric = fmtMs(last)
			}
		}
		lines = append(lines, ui.Row(t.label, st, t.addr, metric, ui.Spark(r)))
	}
	status := "no drops"
	if drops > 0 {
		status = ui.Caution(plural(drops, "drop", "drops"))
	}
	lines = append(lines, "", "  "+ui.Dim(fmtDur(elapsed)+" · "+plural(n, "sample", "samples")+" · ")+status+ui.Dim(" · every "+fmtDur(every)+" · Ctrl-C to stop"))
	return lines
}

const sparkWidth = 40

func cmdWatch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	interval := fs.Duration("i", 5*time.Second, "time between samples (at least 1s)")
	until := fs.Duration("d", 0, "stop after this long (default: until Ctrl-C)")
	noLog := fs.Bool("no-log", false, "don't save samples to the history log")
	logPath := fs.String("log", "", "history log path (default: config dir, or $NETCHECK_HISTORY)")
	asJSON := fs.Bool("json", false, "one JSON line per sample, then a summary line")
	simple := fs.Bool("simple", false, "a live panel instead of the full-screen dashboard")
	parseInterspersed(fs, args)
	*interval = max(*interval, time.Second)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("watch")
	var notes []string

	// Work out what to probe, and how, before the clock starts.
	t := ui.Begin("Starting")
	t.Progress("finding your router…")
	var targets []watchTarget
	gwIP, gwErr := probe.DefaultGateway()
	var gw *probe.Pinger
	gwSilent := false
	if gwErr == nil {
		p, err := probe.NewPinger(ctx, gwIP.String(), []int{80, 443, 53, 22})
		gw, gwSilent = p, errors.Is(err, probe.ErrNoReply)
	}
	t.Progress("checking the internet…")
	inet, inetErr := probe.NewPinger(ctx, "1.1.1.1", []int{443, 53})
	if errors.Is(inetErr, probe.ErrNoReply) {
		if alt, err := probe.NewPinger(ctx, "8.8.8.8", []int{443, 53}); err == nil {
			inet, inetErr = alt, nil
		}
	}
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	switch {
	case gw == nil:
		notes = append(notes, "Couldn't find your router, so only the internet and DNS are watched.")
	case gwSilent && inetErr == nil:
		notes = append(notes, "Your router doesn't answer probes, so only the internet and DNS are watched.")
	default:
		targets = append(targets, watchTarget{history.Gateway, "Gateway", gw.Addr, gw.Once})
	}
	usedTCP := len(targets) > 0 && gw.Method != "icmp"
	if inet == nil {
		ui.Println("  " + ui.Alert("Can't watch the internet: "+inetErr.Error()))
		return 1
	}
	targets = append(targets, watchTarget{history.Internet, "Internet", inet.Addr, inet.Once})
	res := probe.BuildResolvers(gwIP)[0]
	dnsAddr := res.Label
	if res.Addr != "" {
		dnsAddr += " " + res.Addr
	}
	names := probe.DefaultNames
	var nameIdx int
	targets = append(targets, watchTarget{history.DNS, "DNS", dnsAddr, func(ctx context.Context, timeout time.Duration) float64 {
		nameIdx++
		return probe.LookupOnce(ctx, res, names[nameIdx%len(names)], timeout)
	}})
	if usedTCP || inet.Method != "icmp" {
		notes = append(notes, "ICMP isn't available or didn't answer, so some links are timed with TCP connects instead.")
	}

	// The history log. Failing to open it is worth a note, not a failure.
	var log *history.Writer
	path := *logPath
	if !*noLog {
		var err error
		if path == "" {
			path, err = history.DefaultPath()
		}
		if err == nil {
			log, err = history.Open(path, history.DefaultMaxBytes)
		}
		if err != nil {
			notes = append(notes, "Not saving history: "+err.Error())
			log = nil
		} else {
			defer log.Close()
		}
	}
	for _, n := range notes {
		ui.Println("  " + ui.Dim(n))
	}
	if len(notes) > 0 {
		ui.Println("")
	}

	recent := make([][]float64, len(targets))
	var block ui.Block
	live := ui.Interactive() && !*asJSON
	start := time.Now()
	var drops, n int
	var lostRun int
	logFailed := false
	enc := json.NewEncoder(os.Stdout)

	// The full-screen dashboard, when the window is big enough and keys can
	// be read; q, Esc or Ctrl-C leave it. Otherwise the one-panel view.
	runCtx := ctx
	var dash *dashboard
	var leaveDash func()
	redraw := make(chan struct{}, 1)
	if ww, wh := ui.Size(); live && !*simple && ui.StdinTTY() && ww >= dashMinW && wh >= dashMinH {
		route := inet.Addr
		if gwErr == nil {
			route = gwIP.String() + " → " + route
		}
		if ip := probe.LocalIP(); ip != nil {
			route = ip.String() + " → " + route
		}
		saving := "saving to history"
		if log == nil {
			saving = "not saving history"
		}
		dash = newDashboard(targets, start, *interval, route, saving, notes)
		var cancel context.CancelFunc
		runCtx, cancel = context.WithCancel(ctx)
		leaveDash = runDashboard(runCtx, cancel, dash, redraw)
		if gwErr == nil {
			go watchNewDevices(runCtx, dash, gwIP)
		}
	}

	w := watcher{
		clock:    realClock{},
		interval: *interval,
		until:    *until,
		targets:  targets,
		record: func(s history.Sample) {
			n++
			if log != nil && !logFailed {
				if err := log.Append(s); err != nil {
					logFailed = true
					if dash != nil {
						dash.event(s.T, ui.Warn, "stopped saving history")
					} else {
						ui.Println("  " + ui.Dim("Stopped saving history: "+err.Error()))
					}
				}
			}
			if v, ok := s.Get(history.Internet); ok {
				if v < 0 {
					if lostRun++; lostRun == history.MinOutageSamples {
						drops++
					}
				} else {
					lostRun = 0
				}
			}
			for i, t := range targets {
				v, _ := s.Get(t.t)
				recent[i] = tail(append(recent[i], v), sparkWidth)
			}
			switch {
			case *asJSON:
				_ = enc.Encode(s)
			case dash != nil:
				dash.add(s)
				select {
				case redraw <- struct{}{}:
				default:
				}
			case live:
				block.Update(liveLines(targets, recent, n, time.Since(start), drops, *interval))
			default:
				fmt.Println(plainSample(s))
			}
		},
	}
	samples := w.run(runCtx)
	watched := time.Since(start)
	if dash != nil {
		leaveDash()
	} else if live {
		block.End(nil)
	} else if n > 0 && !*asJSON {
		fmt.Println()
	}

	rep := history.Analyze(samples, time.Local)
	st, head, findings := watchVerdict(rep, watched)
	if *asJSON {
		_ = enc.Encode(struct {
			Summary history.Report `json:"summary"`
			Verdict verdict        `json:"verdict"`
		}{rep, verdict{st.String(), head}})
	} else {
		printWatchSummary(targets, rep, watched)
		var extra []string
		if log != nil && !logFailed {
			extra = append(extra, "Saved to "+path+". Run netcheck history for trends.")
		}
		printVerdict(st, head, findings, extra...)
		ui.Println("")
	}
	if rep.Internet != nil && rep.Internet.Samples > 0 && rep.Internet.Lost == rep.Internet.Samples {
		return 1
	}
	return 0
}

// plainSample is the one-line form used when output isn't a terminal.
func plainSample(s history.Sample) string {
	parts := []string{s.T.Format("15:04:05")}
	for _, t := range history.Targets {
		v, ok := s.Get(t)
		if !ok {
			continue
		}
		val := "lost"
		if v >= 0 {
			val = fmt.Sprintf("%.1f", v)
		}
		parts = append(parts, t.String()+" "+val)
	}
	return "  " + strings.Join(parts, "  ")
}

func printWatchSummary(targets []watchTarget, r history.Report, watched time.Duration) {
	if r.Samples == 0 {
		return
	}
	summary := "Watched for " + fmtDur(watched) + " · " + plural(r.Samples, "sample", "samples")
	if ui.Framed() {
		ui.Open(summary)
	} else {
		ui.Println("  " + ui.Dim(summary) + "\n")
	}
	for _, t := range targets {
		s := r.Stats(t.t)
		if s == nil {
			continue
		}
		st, metric := ui.OK, fmtMs(s.MedianMs)
		switch {
		case s.Lost == s.Samples:
			st, metric = ui.Bad, "–"
		case s.LossPct > 2:
			st = ui.Warn
		}
		extra := ui.Dim(fmt.Sprintf("%.1f%% loss", s.LossPct))
		if t.t == history.Internet && len(r.Outages) > 0 {
			extra += ui.Dim(" · " + plural(len(r.Outages), "outage", "outages") + ", " + fmtDur(time.Duration(r.OutageSeconds*float64(time.Second))))
		}
		ui.Println(ui.Row(t.label, st, t.addr, metric, extra))
	}
}
