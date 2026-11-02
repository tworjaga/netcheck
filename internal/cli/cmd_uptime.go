package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/alert"
	"github.com/tworjaga/netcheck/internal/ui"
	"github.com/tworjaga/netcheck/internal/uptime"
)

// uptimeStatus is a target's row status and word.
func uptimeStatus(s uptime.State, now time.Time) (ui.Status, string) {
	switch {
	case s.Checks == 0:
		return ui.Skip, ui.Dim("checking…")
	case s.Down:
		return ui.Bad, "DOWN " + fmtDur(now.Sub(s.Since).Round(time.Second))
	case !s.Last.OK:
		return ui.Warn, fmt.Sprintf("failing (%d)", s.Fails)
	}
	return ui.OK, "up"
}

func certCell(days int) string {
	switch {
	case days == 0:
		return ""
	case days < 0:
		return ui.Alert("<1 d")
	case days < 14:
		return ui.Caution(fmt.Sprintf("%d d", days))
	}
	return fmt.Sprintf("%d d", days)
}

// uptimeTable is one row per target. A single round (--once) has no
// history, so it leaves out the recent-checks and uptime columns.
func uptimeTable(states []uptime.State, width int, now time.Time, single bool) ui.Table {
	sparkW := max(8, min(30, width-90))
	tb := ui.Table{Headers: []string{"Target", "Status", "Time", "Recent", "Uptime", "Cert"}}
	narrow := width < 100 // the sparkline gives way first
	switch {
	case single:
		tb.Headers = []string{"Target", "Status", "Time", "Cert"}
	case narrow:
		tb.Headers = []string{"Target", "Status", "Time", "Uptime", "Cert"}
	}
	for _, s := range states {
		st, word := uptimeStatus(s, now)
		if single && s.Checks > 0 && !s.Last.OK {
			st, word = ui.Bad, "down"
		}
		t := ""
		if s.Checks > 0 {
			if s.Last.OK {
				t = fmtMs(s.Last.Ms)
			} else {
				t = ui.Dim(ui.Cut(s.Last.Detail, map[bool]int{true: 16, false: 22}[narrow]))
			}
		}
		up := ""
		if s.Checks > 0 {
			up = fmt.Sprintf("%.1f%%", s.Uptime())
			if s.Uptime() >= 99.95 {
				up = "100%"
			}
		}
		cells := []string{ui.Cut(s.Target.Name, 32), word, t, ui.Spark(tail(s.Series, sparkW)), up, certCell(s.CertDays)}
		switch {
		case single:
			cells = []string{ui.Cut(s.Target.Name, 32), word, t, certCell(s.CertDays)}
		case narrow:
			cells = []string{ui.Cut(s.Target.Name, 22), word, t, up, certCell(s.CertDays)}
		}
		tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: cells})
	}
	return tb
}

// uptimeDash is the live screen's state: the monitor and the event log.
type uptimeDash struct {
	mu      sync.Mutex
	m       *uptime.Monitor
	events  []uptime.Event
	every   time.Duration
	logPath string
	start   time.Time
}

func (d *uptimeDash) addEvents(evs []uptime.Event) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, evs...)
	if len(d.events) > 200 {
		d.events = d.events[len(d.events)-200:]
	}
}

func eventStatus(e uptime.Event) ui.Status {
	switch e.Kind {
	case "down":
		return ui.Bad
	case "cert":
		return ui.Warn
	}
	return ui.OK
}

func (d *uptimeDash) render(w, h int, now time.Time) []string {
	states := d.m.Snapshot()
	down := 0
	for _, s := range states {
		if s.Down {
			down++
		}
	}
	left := " " + ui.Bold("netcheck") + "  " + ui.Dim("uptime")
	if down > 0 {
		left += "  " + ui.Alert(fmt.Sprintf("%d down", down))
	} else {
		left += "  " + ui.Good("all up")
	}
	right := ui.Dim(now.Format("15:04:05") + "  ·  q quit")
	out := []string{left + strings.Repeat(" ", max(1, w-1-ui.VisWidth(left)-ui.VisWidth(right))) + right}
	sub := fmt.Sprintf("%s  ·  every %s  ·  watching %s", plural(len(states), "target", "targets"), fmtDur(d.every), fmtDur(now.Sub(d.start).Round(time.Second)))
	if d.logPath != "" {
		sub += "  ·  saving to " + d.logPath
	}
	out = append(out, " "+ui.Dim(sub), "")
	tbl := uptimeTable(states, w-8, now, false).Lines(w - 8) // inside the box
	evH := max(4, h-len(out)-len(tbl)-4)
	box := ui.Box("Targets", w-2, len(tbl)+2, tbl)
	for _, l := range box {
		out = append(out, " "+l)
	}
	d.mu.Lock()
	var ev []string
	for i := len(d.events) - 1; i >= 0 && len(ev) < evH-2; i-- {
		e := d.events[i]
		ev = append(ev, ui.Dim(e.Time.Format("Jan 2 15:04"))+"  "+eventStatus(e).Paint(e.Text))
	}
	d.mu.Unlock()
	if len(ev) == 0 {
		ev = []string{ui.Dim("Nothing yet. Targets count as down after failing checks in a row; you'll see it here.")}
	}
	for _, l := range ui.Box("Events", w-2, evH, ev) {
		out = append(out, " "+l)
	}
	for i, l := range out {
		out[i] = ui.Cut(l, w-1)
	}
	return out
}

// runUptimeScreen draws the dashboard every second and on each sample; q,
// Esc or Ctrl-C end it.
func runUptimeScreen(ctx context.Context, cancel context.CancelFunc, d *uptimeDash, redraw <-chan struct{}) func() {
	var scr ui.Screen
	keys, _ := ui.Keys(ctx)
	scr.Enter()
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		draw := func() {
			w, h := ui.Size()
			scr.Draw(d.render(w, h, time.Now()))
		}
		draw()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				draw()
			case <-redraw:
				draw()
			case ev, ok := <-keys:
				if !ok {
					keys = nil
					continue
				}
				if ev.Key == ui.KeyEsc || ev.Key == ui.KeyCtrlC || (ev.Key == ui.KeyRune && (ev.Rune == 'q' || ev.Rune == 'Q')) {
					cancel()
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
		scr.Exit()
	}
}

// --- report ---

type uptimeRow struct {
	Target string          `json:"target"`
	Sum    *uptime.Summary `json:"summary"`
}

// prettyID drops what goes without saying from a target's address.
func prettyID(id string) string {
	for _, p := range []string{"https://", "tcp://"} {
		id = strings.TrimPrefix(id, p)
	}
	id = strings.Replace(id, "://", " ", 1)
	return strings.TrimSuffix(id, "/")
}

func reportTable(rows []uptimeRow) ui.Table {
	tb := ui.Table{Headers: []string{"Target", "Uptime", "Outages", "Longest", "Avg", "Cert"}}
	for _, r := range rows {
		s := r.Sum
		st := ui.OK
		switch {
		case s.Uptime < 99:
			st = ui.Bad
		case s.Uptime < 99.9 || len(s.Outages) > 0:
			st = ui.Warn
		}
		var longest time.Duration
		for _, o := range s.Outages {
			longest = max(longest, o.Length)
		}
		up := fmt.Sprintf("%.2f%%", s.Uptime)
		if s.Good == s.Checks {
			up = "100%"
		}
		lng := ""
		if len(s.Outages) > 0 {
			lng = fmtDur(longest.Round(time.Second))
		}
		avg := ""
		if s.Good > 0 {
			avg = fmtMs(s.AvgMs)
		}
		tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: []string{ui.Cut(prettyID(r.Target), 30), up, fmt.Sprint(len(s.Outages)), lng, avg, certCell(s.CertDays)}})
	}
	return tb
}

func reportVerdict(rows []uptimeRow, days int) (ui.Status, string, []string) {
	if len(rows) == 0 {
		return ui.Skip, fmt.Sprintf("Nothing was checked in the last %s.", plural(days, "day", "days")), nil
	}
	st := ui.OK
	worst, worstUp := "", 101.0
	outages := 0
	var notes []string
	for _, r := range rows {
		outages += len(r.Sum.Outages)
		if r.Sum.Uptime < worstUp {
			worst, worstUp = r.Target, r.Sum.Uptime
		}
		for _, o := range r.Sum.Outages {
			if !o.Ended {
				notes = append(notes, fmt.Sprintf("%s has been down since %s (%s).", prettyID(r.Target), o.Start.Format("Jan 2 15:04"), o.Detail))
				st = ui.Bad
			}
		}
	}
	msg := fmt.Sprintf("Over the last %s: %s, %s.", plural(days, "day", "days"), plural(len(rows), "target", "targets"), plural(outages, "outage", "outages"))
	if worstUp < 99.95 {
		msg += fmt.Sprintf(" The least available was %s at %.2f%%.", prettyID(worst), worstUp)
		st = max(st, ui.Warn)
	}
	notes = append(notes, "Uptime counts only while netcheck was running; it can't tell what happened when this machine was off.")
	return st, msg, notes
}

func cmdUptime(args []string) int {
	fs := flag.NewFlagSet("uptime", flag.ExitOnError)
	common := adv.Register(fs)
	every := fs.Duration("i", 30*time.Second, "time between checks")
	downAfter := fs.Int("down-after", 3, "failed checks in a row before a target counts as down")
	certWarn := fs.Int("cert", 14, "warn when a certificate has fewer days left (0: never)")
	once := fs.Bool("once", false, "check everything once and exit (for scripts)")
	report := fs.Bool("report", false, "sum up the saved history instead of checking")
	days := fs.Int("days", 7, "with --report: how many days back")
	noLog := fs.Bool("no-log", false, "don't save the results")
	af := addAlertFlags(fs)
	pos := parseInterspersed(fs, args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck uptime: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck uptime <https://... | tcp://host:port | ping://host | dns://name> ... | -f servers.txt [-i 30s] [--once]")
		fmt.Fprintln(os.Stderr, "       netcheck uptime --report [--days 7]")
		return 2
	}
	logPath, _ := uptime.DefaultPath()
	uptime.UserAgent = "netcheck-uptime/" + version

	if *report {
		ui.SetQuiet(common.JSON)
		samples, err := uptime.ReadLog(logPath, time.Now().AddDate(0, 0, -*days))
		ui.Title("uptime report")
		if err != nil {
			ui.Verdict(ui.Skip, "No history yet: run `netcheck uptime` with some targets first; it saves the results to "+logPath+".")
			ui.Println("")
			return 0
		}
		sums := uptime.Summarize(samples, *downAfter)
		var rows []uptimeRow
		for id, s := range sums {
			rows = append(rows, uptimeRow{Target: id, Sum: s})
		}
		sort.Slice(rows, func(i, j int) bool {
			return rows[i].Sum.Uptime < rows[j].Sum.Uptime || rows[i].Sum.Uptime == rows[j].Sum.Uptime && rows[i].Target < rows[j].Target
		})
		st, msg, notes := reportVerdict(rows, *days)
		if len(rows) > 0 {
			ui.Open(fmt.Sprintf("Last %s", plural(*days, "day", "days")))
			for _, l := range reportTable(rows).Lines(ui.PanelWidth()) {
				ui.Println(l)
			}
			ui.Close()
		}
		ui.Verdict(st, msg, notes...)
		ui.Println("")
		if common.JSON {
			adv.Envelope{Tool: "uptime", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: rows}.Write(os.Stdout)
		}
		return 0
	}

	var lines []string
	lines = append(lines, pos...)
	if common.File != "" {
		fl, err := readListFile(common.File)
		if err != nil {
			return usage(err.Error())
		}
		lines = append(lines, fl...)
	}
	// Alert channels: from the flags, and "alert ..." lines in the file.
	targetLines, fileSpecs := splitAlertLines(lines)
	chans, err := buildChannels(append(af.specs(), fileSpecs...))
	if err != nil {
		return usage(err.Error())
	}
	if *af.test {
		return runTestAlert(ctx, "uptime", chans, common.JSON)
	}
	var targets []uptime.Target
	seen := map[string]bool{}
	for _, l := range targetLines {
		t, err := uptime.ParseTarget(l)
		if err != nil {
			return usage(err.Error())
		}
		if seen[t.ID] {
			continue
		}
		seen[t.ID] = true
		targets = append(targets, t)
	}
	switch {
	case len(targets) == 0:
		return usage("give something to watch")
	case *every < 5*time.Second:
		return usage("-i is at least 5s")
	case *downAfter < 1 || *downAfter > 20:
		return usage("--down-after is 1 to 20")
	}
	m := uptime.NewMonitor(targets, *downAfter, *certWarn)

	if *once {
		ui.SetQuiet(common.JSON)
		ui.Title("uptime")
		t := ui.Begin("Checking")
		t.Progress(plural(len(targets), "target", "targets") + "…")
		var mu sync.Mutex
		var samples []uptime.Sample
		cctx, cancel := context.WithCancel(ctx)
		uptime.Run(cctx, targets, time.Hour, func(s uptime.Sample) {
			mu.Lock()
			samples = append(samples, s)
			done := len(samples) == len(targets)
			mu.Unlock()
			m.Add(s)
			if done {
				cancel()
			}
		})
		cancel()
		t.Clear()
		if ctx.Err() != nil {
			return 130
		}
		if !*noLog {
			if l, err := uptime.OpenLog(logPath); err == nil {
				for _, s := range samples {
					l.Append(s)
				}
				l.Close()
			}
		}
		states := m.Snapshot()
		failing := 0
		for _, s := range states {
			if !s.Last.OK {
				failing++
			}
		}
		ui.Open(plural(len(targets), "target", "targets"))
		for _, l := range uptimeTable(states, ui.PanelWidth(), time.Now(), true).Lines(ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
		st, msg := ui.OK, fmt.Sprintf("All %s answer.", plural(len(targets), "target", "targets"))
		if len(targets) == 1 {
			msg = "The target answers."
		}
		var notes []string
		if failing > 0 {
			st, msg = ui.Bad, fmt.Sprintf("%d of %s %s.", failing, plural(len(targets), "target", "targets"), map[bool]string{true: "fails", false: "fail"}[failing == 1])
			for _, s := range states {
				if !s.Last.OK {
					notes = append(notes, s.Target.Name+": "+s.Last.Detail+".")
				}
			}
		}
		for _, s := range states {
			if s.CertDays != 0 && s.CertDays < *certWarn {
				st = max(st, ui.Warn)
				notes = append(notes, fmt.Sprintf("%s: the certificate expires in %s.", s.Target.Name, plural(max(s.CertDays, 0), "day", "days")))
			}
		}
		ui.Verdict(st, msg, notes...)
		ui.Println("")
		if common.JSON {
			adv.Envelope{Tool: "uptime", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: samples}.Write(os.Stdout)
		}
		return adv.ExitCode(st.String(), nil)
	}

	// Watching: the dashboard on a terminal, one line per event otherwise.
	var log *uptime.Log
	if !*noLog {
		var err error
		if log, err = uptime.OpenLog(logPath); err != nil {
			fmt.Fprintln(os.Stderr, "netcheck uptime: can't save the history: "+err.Error())
		} else {
			defer log.Close()
		}
	}
	shownLog := logPath
	if log == nil {
		shownLog = ""
	}
	d := &uptimeDash{m: m, every: *every, logPath: shownLog, start: time.Now()}
	live := ui.Interactive() && !common.JSON
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	redraw := make(chan struct{}, 1)
	onEvent := func(evs []uptime.Event) {
		d.addEvents(evs)
		for _, e := range evs {
			if len(chans) == 0 {
				break
			}
			go func() {
				ae := alert.Event{Time: e.Time, Kind: e.Kind, Target: e.ID, Name: e.Name, Text: e.Text, Detail: e.Detail, DownFor: e.DownFor}
				for _, r := range alert.Send(ctx, chans, ae) {
					if r.Error != "" {
						fail := uptime.Event{Time: time.Now(), Kind: "cert", Text: "Alert by " + r.Channel + " failed: " + r.Error}
						d.addEvents([]uptime.Event{fail})
						if !live && !common.JSON {
							fmt.Printf("%s  %s\n", fail.Time.Format("2006-01-02 15:04:05"), fail.Text)
						}
					}
				}
			}()
		}
		for _, e := range evs {
			switch {
			case common.JSON:
				printJSON(e)
			case !live:
				fmt.Printf("%s  %s\n", e.Time.Format("2006-01-02 15:04:05"), e.Text)
			}
		}
	}
	if live {
		exit := runUptimeScreen(ctx, cancel, d, redraw)
		defer exit()
	} else if !common.JSON {
		fmt.Printf("netcheck uptime: watching %s every %s; one line per change. Ctrl-C stops.\n", plural(len(targets), "target", "targets"), *every)
	}
	uptime.Run(ctx, targets, *every, func(s uptime.Sample) {
		if log != nil {
			log.Append(s)
		}
		onEvent(m.Add(s))
		select {
		case redraw <- struct{}{}:
		default:
		}
	})
	return 0
}

// readListFile reads a servers file: one entry a line, # starts a comment.
func readListFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0]); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, sc.Err()
}

// loadWatchFile reads targets and "alert ..." lines, as uptime -f does.
func loadWatchFile(path string) ([]uptime.Target, []alert.Channel, error) {
	lines, err := readListFile(path)
	if err != nil {
		return nil, nil, err
	}
	tl, specs := splitAlertLines(lines)
	chans, err := buildChannels(specs)
	if err != nil {
		return nil, nil, err
	}
	var targets []uptime.Target
	seen := map[string]bool{}
	for _, l := range tl {
		t, err := uptime.ParseTarget(l)
		if err != nil {
			return nil, nil, err
		}
		if !seen[t.ID] {
			seen[t.ID] = true
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return nil, nil, fmt.Errorf("%s lists nothing to watch", path)
	}
	return targets, chans, nil
}
