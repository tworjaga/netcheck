package cli

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/history"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// The full-screen watch dashboard: a big internet chart, the current
// numbers, the router and DNS, and a log of what happened. It only renders;
// cmdWatch feeds it samples and draws what it returns.

// dashMinW and dashMinH are the smallest window the dashboard fits; below
// that, watch uses its one-panel view.
const (
	dashMinW = 70
	dashMinH = 20
	dashKeep = 600 // samples kept per link for the chart
)

type dashEvent struct {
	at   time.Time
	st   ui.Status
	text string
}

type dashLink struct {
	t        watchTarget
	series   []float64
	sum      float64
	ok, lost int
	lostRun  int
}

type dashboard struct {
	mu     sync.Mutex
	links  []*dashLink
	events []dashEvent
	start  time.Time
	every  time.Duration
	route  string // "192.168.0.123 → 192.168.0.1 → 1.1.1.1"
	saving string // where history goes, or why it doesn't
	drops  int
	downAt time.Time // the internet is down since then (zero: it's up)
}

func newDashboard(targets []watchTarget, start time.Time, every time.Duration, route, saving string, notes []string) *dashboard {
	d := &dashboard{start: start, every: every, route: route, saving: saving}
	for _, t := range targets {
		d.links = append(d.links, &dashLink{t: t})
	}
	d.events = append(d.events, dashEvent{start, ui.OK, "watch started"})
	for _, n := range notes {
		d.events = append(d.events, dashEvent{start, ui.Skip, n})
	}
	return d
}

func (d *dashboard) link(t history.Target) *dashLink {
	for _, l := range d.links {
		if l.t.t == t {
			return l
		}
	}
	return nil
}

func (d *dashboard) note(at time.Time, st ui.Status, text string) {
	d.events = append(d.events, dashEvent{at, st, text})
	if len(d.events) > 200 {
		d.events = d.events[len(d.events)-200:]
	}
}

// median of the non-lost values.
func median(vals []float64) float64 {
	var v []float64
	for _, x := range vals {
		if x >= 0 {
			v = append(v, x)
		}
	}
	if len(v) == 0 {
		return 0
	}
	sort.Float64s(v)
	return v[len(v)/2]
}

// add takes one sample and notes what's worth telling: the internet going
// down and coming back, latency spikes, the router or DNS missing a probe.
func (d *dashboard) add(s history.Sample) {
	d.mu.Lock()
	defer d.mu.Unlock()
	at := s.T
	for _, l := range d.links {
		v, measured := s.Get(l.t.t)
		if !measured {
			continue
		}
		prev := median(tail(l.series, 30))
		enough := l.ok >= 5
		l.series = tail(append(l.series, v), dashKeep)
		if v < 0 {
			l.lost++
			l.lostRun++
		} else {
			l.ok++
			l.sum += v
		}
		switch l.t.t {
		case history.Internet:
			switch {
			case v < 0 && l.lostRun == history.MinOutageSamples:
				d.drops++
				d.downAt = at.Add(-time.Duration(l.lostRun-1) * d.every)
				d.note(d.downAt, ui.Bad, "internet down")
			case v >= 0 && !d.downAt.IsZero():
				d.note(at, ui.OK, "internet back after "+fmtDur(at.Sub(d.downAt)))
				d.downAt = time.Time{}
			case v >= 0 && enough && v > max(150, 3*prev):
				d.note(at, ui.Warn, fmt.Sprintf("spike %s (usually %s)", fmtMs(v), fmtMs(prev)))
			}
		default:
			if v < 0 && l.lostRun == 1 {
				d.note(at, ui.Warn, strings.ToLower(l.t.label)+" missed a probe")
			}
		}
		if v >= 0 {
			l.lostRun = 0
		}
	}
}

// statLine is "avg 18 ms · 0.0% loss" for a link.
func (l *dashLink) statLine() string {
	if l.ok == 0 && l.lost == 0 {
		return ui.Dim("waiting…")
	}
	avg := "–"
	if l.ok > 0 {
		avg = fmtMs(l.sum / float64(l.ok))
	}
	loss := float64(l.lost) / float64(l.ok+l.lost) * 100
	ls := fmt.Sprintf("%.1f%% loss", loss)
	if loss > 2 {
		ls = ui.Caution(ls)
	}
	return ui.Dim("avg ") + avg + ui.Dim(" · ") + ls
}

// last is the newest reading and its status.
func (l *dashLink) last() (string, ui.Status) {
	if len(l.series) == 0 {
		return "–", ui.Skip
	}
	v := l.series[len(l.series)-1]
	switch {
	case v < 0:
		return "lost", ui.Bad
	case v > 150:
		return fmtMs(v), ui.Warn
	}
	return fmtMs(v), ui.OK
}

// render draws the dashboard for a w×h window at time now.
func (d *dashboard) render(w, h int, now time.Time) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	usable := w - 2 // a column of margin each side
	var out []string

	// Header: name, route, the clock and how to leave.
	left := " " + ui.Bold("netcheck") + "  " + ui.Dim("watch")
	right := ui.Dim(now.Format("15:04:05") + "  ·  q quit")
	out = append(out, left+strings.Repeat(" ", max(1, w-1-ui.VisWidth(left)-ui.VisWidth(right)))+right)
	out = append(out, " "+ui.Dim(d.route+"  ·  every "+fmtDur(d.every)+"  ·  "+d.saving), "")

	// Top row: the internet chart and the current numbers beside it.
	nowW := 26
	chartW := usable - nowW - 1
	topH := max(8, h-len(out)-7)
	in := d.link(history.Internet)
	var chart []string
	title := "Internet"
	if in != nil {
		title += " " + in.t.addr
		for _, l := range ui.LatencyChart(in.series, topH-4, chartW-2) {
			chart = append(chart, strings.TrimPrefix(l, "  "))
		}
		chart = append(chart, "", in.statLine())
	}
	if d.downAt.IsZero() {
		title += "  " + ui.Good(ui.Pick("● up", "up"))
	} else {
		title += "  " + ui.Alert(ui.Pick("● down", "DOWN")) + ui.Dim(" for "+fmtDur(now.Sub(d.downAt)))
	}
	var nowLines []string
	for _, l := range d.links {
		v, st := l.last()
		nowLines = append(nowLines, ui.Pad(l.t.label, 10)+st.Sym()+" "+ui.Pad(v, 8))
	}
	drops := fmt.Sprint(d.drops)
	if d.drops > 0 {
		drops = ui.Caution(drops)
	}
	samples := 0
	if in != nil {
		samples = in.ok + in.lost
	}
	nowLines = append(nowLines, "",
		ui.Pad(ui.Dim("Drops"), 12)+drops,
		ui.Pad(ui.Dim("Samples"), 12)+fmt.Sprint(samples),
		ui.Pad(ui.Dim("Watching"), 12)+fmtDur(now.Sub(d.start)))
	for _, l := range ui.Beside(1, ui.Box(title, chartW, topH, chart), ui.Box("Now", nowW, topH, nowLines)) {
		out = append(out, " "+l)
	}

	// Bottom row: router, DNS and what happened.
	// Narrow windows give the event log the room; wide ones split evenly.
	smallW := (usable - 2) / 3
	if usable < 100 {
		smallW = 16
	}
	evW := usable - 2*smallW - 2
	small := func(t history.Target, name string) []string {
		l := d.link(t)
		if l == nil {
			return ui.Box(name, smallW, 6, []string{ui.Dim("not watched")})
		}
		avg, loss := l.stats()
		return ui.Box(name, smallW, 6, []string{ui.Dim(l.t.addr), ui.Spark(tail(l.series, smallW-4)), avg, loss})
	}
	var evLines []string
	for i := len(d.events) - 1; i >= 0 && len(evLines) < 4; i-- {
		e := d.events[i]
		evLines = append(evLines, ui.Dim(e.at.Format("15:04"))+" "+e.st.Paint(e.text))
	}
	for _, l := range ui.Beside(1, small(history.Gateway, "Router"), small(history.DNS, "DNS"), ui.Box("Events", evW, 6, evLines)) {
		out = append(out, " "+l)
	}
	for i, l := range out {
		out[i] = ui.Cut(l, w-1)
	}
	return out
}

// stats is the average and the loss as two short lines, for small panels.
func (l *dashLink) stats() (string, string) {
	if l.ok == 0 && l.lost == 0 {
		return ui.Dim("waiting…"), ""
	}
	avg := "–"
	if l.ok > 0 {
		avg = fmtMs(l.sum / float64(l.ok))
	}
	loss := float64(l.lost) / float64(l.ok+l.lost) * 100
	ls := fmt.Sprintf("%.1f%% loss", loss)
	if loss > 2 {
		ls = ui.Caution(ls)
	}
	return ui.Dim("avg ") + avg, ls
}

// event adds a line to the event log from outside a sample (a failed
// history write, say).
func (d *dashboard) event(at time.Time, st ui.Status, text string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.note(at, st, text)
}

// runDashboard takes over the window and redraws the dashboard every second,
// after each sample (a send on redraw) and when the window is resized. q,
// Esc or Ctrl-C call cancel. The returned function waits for the drawing to
// stop and gives the window back.
func runDashboard(ctx context.Context, cancel context.CancelFunc, d *dashboard, redraw <-chan struct{}) func() {
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

// newDeviceCheck is how often watch looks for devices it hasn't seen.
const newDeviceCheck = time.Minute

// unknownDevices are the neighbour-table entries on subnet that the devices
// file doesn't know and that haven't been reported yet (seen is updated).
func unknownDevices(entries []probe.ARPEntry, known *knownNetwork, subnet *net.IPNet, seen map[string]bool) []probe.ARPEntry {
	var out []probe.ARPEntry
	for _, e := range entries {
		if subnet != nil && !subnet.Contains(e.IP) {
			continue
		}
		if known.Devices[e.MAC] != nil || seen[e.MAC] {
			continue
		}
		seen[e.MAC] = true
		out = append(out, e)
	}
	return out
}

// watchNewDevices puts devices that join while watch runs into the event
// log, checking the neighbour table once a minute against the list
// `netcheck devices` remembered for this network. It never writes that list.
func watchNewDevices(ctx context.Context, d *dashboard, gw net.IP) {
	path, err := devicesPath()
	if err != nil {
		return
	}
	store, err := loadDevices(path)
	if err != nil {
		return
	}
	entries := probe.ARPTable(ctx)
	key := ""
	for _, e := range entries {
		if e.IP.Equal(gw) {
			key = "router " + e.MAC
		}
	}
	known := store.Networks[key]
	if known == nil {
		d.event(time.Now(), ui.Skip, "run netcheck devices once for new-device alerts")
		return
	}
	_, subnet, _ := net.ParseCIDR(known.Subnet)
	seen := map[string]bool{}
	for {
		for _, e := range unknownDevices(entries, known, subnet, seen) {
			d.event(time.Now(), ui.Warn, "new device "+e.IP.String())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(newDeviceCheck):
		}
		entries = probe.ARPTable(ctx)
	}
}
