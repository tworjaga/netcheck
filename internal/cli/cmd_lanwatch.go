package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/alert"
	"github.com/tworjaga/netcheck/internal/lanwatch"
	"github.com/tworjaga/netcheck/internal/ui"
)

// Test seams.
var (
	takeSnapshot = lanwatch.Take
)

// eventTitles name each kind of change for notifications.
var eventTitles = map[string]string{
	"joined": "New device on the network", "left": "Device left the network", "spoof": "Possible ARP spoofing",
	"gateway": "Default gateway changed", "dns": "DNS servers changed", "public-ip": "Public address changed",
	"dhcp": "Second DHCP server", "upnp-open": "Port opened to the internet", "upnp-closed": "Port closed",
}

func levelStatus(l string) ui.Status {
	switch l {
	case "bad":
		return ui.Bad
	case "warn":
		return ui.Warn
	}
	return ui.OK
}

// lanDash is the live screen.
type lanDash struct {
	mu      sync.Mutex
	snap    lanwatch.Snapshot
	first   map[string]time.Time // when each device was first seen this run
	events  []lanwatch.Event
	every   time.Duration
	start   time.Time
	next    time.Time
	logPath string
}

func (d *lanDash) update(s lanwatch.Snapshot, evs []lanwatch.Event, next time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.snap, d.next = s, next
	for mac := range s.Devices {
		if _, ok := d.first[mac]; !ok {
			d.first[mac] = s.Time
		}
	}
	d.events = append(d.events, evs...)
	if len(d.events) > 300 {
		d.events = d.events[len(d.events)-300:]
	}
}

func (d *lanDash) render(w, h int, now time.Time) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.snap
	bad := 0
	for _, e := range d.events {
		if e.Level == "bad" {
			bad++
		}
	}
	left := " " + ui.Bold("netcheck") + "  " + ui.Dim("lanwatch")
	if bad > 0 {
		left += "  " + ui.Alert(plural(bad, "alarm", "alarms"))
	}
	right := ui.Dim(now.Format("15:04:05") + "  ·  q quit")
	out := []string{left + strings.Repeat(" ", max(1, w-1-ui.VisWidth(left)-ui.VisWidth(right))) + right}
	sub := fmt.Sprintf("every %s  ·  watching %s", fmtDur(d.every), fmtDur(now.Sub(d.start).Round(time.Second)))
	if left := d.next.Sub(now); left > 0 {
		sub += fmt.Sprintf("  ·  next look in %s", fmtDur(left.Round(time.Second)))
	}
	out = append(out, " "+ui.Dim(sub), "")

	upnp := ui.Dim("off")
	if s.UPnP {
		upnp = fmt.Sprintf("on, %s", plural(len(s.Mappings), "port forwarded", "ports forwarded"))
	}
	info := []string{
		ui.Pad(ui.Dim("Router"), 11) + s.Gateway + "  " + ui.Dim(s.GatewayMAC),
		ui.Pad(ui.Dim("DNS"), 11) + ui.Cut(strings.Join(s.DNS, ", "), w-20),
		ui.Pad(ui.Dim("Public IP"), 11) + firstNonEmpty(s.PublicIP, ui.Dim("unknown")),
		ui.Pad(ui.Dim("UPnP"), 11) + upnp,
		ui.Pad(ui.Dim("Devices"), 11) + fmt.Sprint(len(s.Devices)),
	}
	for _, l := range ui.Box("Network", w-2, len(info)+2, info) {
		out = append(out, " "+l)
	}

	var macs []string
	for mac := range s.Devices {
		macs = append(macs, mac)
	}
	sort.Slice(macs, func(i, j int) bool { return ipKey(s.Devices[macs[i]].IP) < ipKey(s.Devices[macs[j]].IP) })
	tb := ui.Table{Headers: []string{"Address", "Device", "MAC", "Here since"}}
	for _, mac := range macs {
		dv := s.Devices[mac]
		name := firstNonEmpty(dv.Name, dv.Vendor)
		if name == "" {
			name = ui.Dim("unknown")
		}
		since := d.first[mac]
		when := since.Format("15:04")
		if since.Equal(d.start) || !since.After(d.start.Add(time.Second)) {
			when = ui.Dim("start")
		}
		tb.Rows = append(tb.Rows, ui.TableRow{Status: ui.OK, Cells: []string{dv.IP, ui.Cut(name, 26), mac, when}})
	}
	evH := max(5, min(12, h/3))
	devH := max(4, h-len(out)-evH-1)
	rows := tb.Lines(w - 8)
	if len(rows) > devH-2 {
		more := len(rows) - (devH - 3)
		rows = append(rows[:devH-3], ui.Dim(fmt.Sprintf("  … and %d more", more)))
	}
	for _, l := range ui.Box("Devices", w-2, devH, rows) {
		out = append(out, " "+l)
	}
	var ev []string
	for i := len(d.events) - 1; i >= 0 && len(ev) < evH-2; i-- {
		e := d.events[i]
		ev = append(ev, ui.Dim(e.Time.Format("Jan 2 15:04"))+"  "+levelStatus(e.Level).Paint(e.Text))
	}
	if len(ev) == 0 {
		ev = []string{ui.Dim("Nothing has changed yet. New devices, ARP spoofing, DHCP, DNS, gateway and UPnP changes show up here.")}
	}
	for _, l := range ui.Box("Events", w-2, evH, ev) {
		out = append(out, " "+l)
	}
	for i, l := range out {
		out[i] = ui.Cut(l, w-1)
	}
	return out
}

func ipKey(ip string) string {
	var b strings.Builder
	for _, p := range strings.Split(ip, ".") {
		fmt.Fprintf(&b, "%03s.", p)
	}
	return b.String()
}

func lanwatchLogPath() string {
	if p := os.Getenv("NETCHECK_LANWATCH_LOG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "netcheck", "lanwatch.jsonl")
}

func cmdLanwatch(args []string) int {
	fs := flag.NewFlagSet("lanwatch", flag.ExitOnError)
	common := adv.Register(fs)
	every := fs.Duration("i", 2*time.Minute, "time between looks at the network")
	leave := fs.Duration("leave", 15*time.Minute, "how long a device must be missing to count as gone")
	dhcpEvery := fs.Int("dhcp-every", 5, "look for DHCP servers every this many rounds (0: never)")
	alertAll := fs.Bool("alert-all", false, "alert on every change, not just warnings (devices joining and leaving, public address)")
	noLog := fs.Bool("no-log", false, "don't save the events")
	af := addAlertFlags(fs)
	pos := parseInterspersed(fs, args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck lanwatch: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck lanwatch [-i 2m] [--notify] [--webhook URL] [--email ...] [--test-alert]")
		return 2
	}
	if len(pos) > 0 {
		return usage("takes no arguments; it watches the network this machine is on")
	}
	if *every < 30*time.Second {
		return usage("-i is at least 30s")
	}
	chans, err := buildChannels(af.specs())
	if err != nil {
		return usage(err.Error())
	}
	if *af.test {
		return runTestAlert(ctx, "lanwatch", chans, common.JSON)
	}
	if !common.JSON {
		ui.Title("lanwatch")
	}
	known := knownMACs()
	t := ui.Begin("Looking")
	t.Progress("at the network for the first time…")
	base, err := takeSnapshot(ctx, *dhcpEvery > 0)
	t.Clear()
	if err != nil {
		ui.Verdict(ui.Bad, "Couldn't look at the network: "+err.Error()+".")
		ui.Println("")
		return 1
	}
	if gw := parseIP(base.Gateway); !lanwatch.Own(gw) {
		ui.Verdict(ui.Bad, "This network's router ("+base.Gateway+") has a public address; lanwatch only watches private networks.")
		ui.Println("")
		return 1
	}
	var logf *os.File
	logPath := ""
	if !*noLog {
		if p := lanwatchLogPath(); p != "" {
			os.MkdirAll(filepath.Dir(p), 0o755)
			if f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				logf, logPath = f, p
				defer f.Close()
			}
		}
	}
	d := &lanDash{first: map[string]time.Time{}, every: *every, start: base.Time, logPath: logPath}
	d.update(base, nil, time.Now().Add(*every))
	live := ui.Interactive() && !common.JSON
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	redraw := make(chan struct{}, 1)
	if live {
		exit := runLanScreen(ctx, cancel, d, redraw)
		defer exit()
	} else if !common.JSON {
		fmt.Printf("netcheck lanwatch: watching %s (%s, router %s) every %s; one line per change. Ctrl-C stops.\n",
			plural(len(base.Devices), "device", "devices"), base.Gateway, base.GatewayMAC, *every)
	}
	if known == nil && !common.JSON && !live {
		fmt.Println("netcheck lanwatch: run `netcheck devices` once so devices joining can be told apart from ones seen before.")
	}
	gone := map[string]time.Time{}
	prev := base
	for round := 1; ; round++ {
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(*every):
		}
		cur, err := takeSnapshot(ctx, *dhcpEvery > 0 && round%*dhcpEvery == 0)
		if ctx.Err() != nil {
			return 0
		}
		if err != nil {
			continue
		}
		if cur.DHCP == nil {
			cur.DHCP = prev.DHCP // not asked this round
		}
		evs := lanwatch.Diff(prev, cur, known, gone, *leave)
		prev = cur
		d.update(cur, evs, time.Now().Add(*every))
		for _, e := range evs {
			if logf != nil {
				b, _ := json.Marshal(e)
				logf.Write(append(b, '\n'))
			}
			switch {
			case common.JSON:
				printJSON(e)
			case !live:
				fmt.Printf("%s  %s\n", e.Time.Format("2006-01-02 15:04:05"), e.Text)
			}
			if len(chans) > 0 && (e.Level != "info" || *alertAll) {
				ae := alert.Event{Time: e.Time, Kind: e.Kind, Target: "lan", Name: eventTitles[e.Kind], Text: e.Text, Detail: e.Detail}
				go func() {
					for _, r := range alert.Send(ctx, chans, ae) {
						if r.Error != "" {
							d.update(prev, []lanwatch.Event{{Time: time.Now(), Kind: "alert", Level: "warn", Text: "Alert by " + r.Channel + " failed: " + r.Error}}, d.next)
						}
					}
				}()
			}
		}
		select {
		case redraw <- struct{}{}:
		default:
		}
	}
}

// runLanScreen draws the dashboard every second and after each look; q,
// Esc or Ctrl-C end it.
func runLanScreen(ctx context.Context, cancel context.CancelFunc, d *lanDash, redraw <-chan struct{}) func() {
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
