package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// doctorSpeedTime is how long Doctor's speed test runs in each direction:
// shorter than `netcheck speed`, still past TCP's warm-up.
const doctorSpeedTime = 6 * time.Second

// doctorData is everything Doctor measured. A nil pointer means that check
// didn't run (skipped, unsupported, or interrupted).
type doctorData struct {
	GatewayFound bool
	Gateway      *probe.PingResult
	Internet     *probe.PingResult
	DNS          []probe.DNSResult
	Wifi         *probe.WifiInfo
	IPv6         *probe.IPv6Result
	NAT          *probe.NATInfo
	Speed        *probe.SpeedResult
	Readiness    []useVerdict
}

func (d doctorData) online() bool { return d.Internet != nil && d.Internet.Received > 0 }

// doctorReport is the JSON shape. Fields from earlier versions keep their
// names; everything else was added alongside them.
type doctorReport struct {
	Gateway   *probe.PingResult  `json:"gateway,omitempty"`
	Internet  *probe.PingResult  `json:"internet,omitempty"`
	DNS       []probe.DNSResult  `json:"dns,omitempty"`
	Readiness []useVerdict       `json:"readiness,omitempty"`
	Verdict   verdict            `json:"verdict"`
	Findings  []verdict          `json:"findings"`
	Wifi      *probe.WifiInfo    `json:"wifi,omitempty"`
	IPv6      *probe.IPv6Result  `json:"ipv6,omitempty"`
	NAT       *probe.NATInfo     `json:"nat,omitempty"`
	Speed     *probe.SpeedResult `json:"speed,omitempty"`
	SQM       *sqmSettings       `json:"sqm,omitempty"`
	Fast      bool               `json:"fast"`
	Notes     []string           `json:"notes,omitempty"`
}

// doctorFindings judges everything Doctor measured. Findings come out in
// order of seriousness, so the first Bad (else the first Warn) is the
// headline: no connection, then DNS, then the link from the Wi-Fi outwards,
// then speed and what the connection is good for, and last the things that
// only matter for some uses (IPv6, crowded channel, NAT).
func doctorFindings(d doctorData) []finding {
	var fs []finding
	add := func(st ui.Status, msg string) { fs = append(fs, finding{st, msg}) }

	gw, inet := d.Gateway, d.Internet
	gwReplied := gw != nil && gw.Received > 0
	weakWifi := d.Wifi != nil && d.Wifi.Connected && d.Wifi.SignalDBm != 0 && d.Wifi.SignalDBm < -75

	// 1. Is there a connection at all?
	switch {
	case inet == nil:
	case !d.online() && !gwReplied && weakWifi:
		add(ui.Bad, fmt.Sprintf("Can't reach your router or the internet, and the Wi-Fi signal is very weak (%d dBm). Move closer to the router.", d.Wifi.SignalDBm))
	case !d.online() && !gwReplied:
		add(ui.Bad, "Can't reach your router or the internet. Check the Wi-Fi or cable, and that the router has power.")
	case !d.online():
		add(ui.Bad, "Your router answers but the internet doesn't. That points to your ISP or the router's uplink; try restarting the router.")
	}

	// 2. Names.
	if d.online() && len(d.DNS) > 0 {
		if st, msg, _ := dnsVerdict(d.DNS); st != ui.OK {
			add(st, msg)
		}
	}

	// 3. The link, from the Wi-Fi outwards. Weak signal explains loss to the
	// router, so they're told as one story.
	gwLossy := gwReplied && gw.LossPct > 2
	switch {
	case weakWifi && gwLossy:
		add(ui.Warn, fmt.Sprintf("Weak Wi-Fi (%d dBm) is losing packets: %.0f%% to your router. Move closer to the router or add an access point.", d.Wifi.SignalDBm, gw.LossPct))
	case weakWifi && d.online():
		add(ui.Warn, fmt.Sprintf("Your Wi-Fi signal is %s (%d dBm). Move closer to the router or add an access point; weak signal causes slow speeds and drops.", probe.SignalQuality(d.Wifi.SignalDBm), d.Wifi.SignalDBm))
	case gwLossy:
		add(ui.Warn, fmt.Sprintf("Packet loss to your router (%.0f%%). That usually means weak Wi-Fi or interference.", gw.LossPct))
	}
	if gwReplied && !gwLossy && gw.AvgMs > 25 {
		add(ui.Warn, fmt.Sprintf("The link to your router is slow (%s). Move closer, or check for Wi-Fi congestion.", fmtMs(gw.AvgMs)))
	}
	if d.online() {
		switch {
		case inet.LossPct > 2 && !gwLossy:
			add(ui.Warn, fmt.Sprintf("%.0f%% packet loss to the internet but none to your router, so it's past your home network: the line or your ISP.", inet.LossPct))
		case inet.AvgMs > 120:
			add(ui.Warn, fmt.Sprintf("High latency to the internet (%s). Fine for browsing, rough for calls and games.", fmtMs(inet.AvgMs)))
		case inet.JitterMs > 30:
			add(ui.Warn, fmt.Sprintf("Latency is unstable (jitter %s), which hurts calls and gaming.", fmtMs(inet.JitterMs)))
		}
	}

	// 4. Speed under load.
	if s := d.Speed; s != nil && s.Error == "" {
		if st, msg := speedVerdict(*s); st != ui.OK {
			add(st, msg)
		}
	}

	// 5. What it's good for, when something falls short.
	for _, u := range d.Readiness {
		if u.Status == ui.Bad || u.Status == ui.Warn {
			add(ui.Warn, readinessLine(d.Readiness))
			break
		}
	}

	// 6. Things that matter only for some uses.
	if v := d.IPv6; v != nil && d.online() {
		if st, msg := ipv6Verdict(*v); st == ui.Warn || st == ui.Bad {
			add(ui.Warn, msg)
		}
	}
	if w := d.Wifi; w != nil && w.Connected && w.Crowding == "crowded" && !weakWifi {
		if _, msg, _ := wifiVerdict(*w); msg != "" {
			add(ui.Warn, msg)
		}
	}
	if n := d.NAT; n != nil && (n.Kind == "cgnat" || n.Kind == "double") {
		add(ui.Warn, natFinding(*n, d.IPv6))
	}
	return fs
}

// natFinding explains CGNAT or double NAT in terms of what it breaks.
func natFinding(n probe.NATInfo, v6 *probe.IPv6Result) string {
	msg := "Your ISP shares one public address between many customers (carrier-grade NAT). Browsing is fine, but port forwarding, hosting game servers and some peer-to-peer apps won't work."
	if n.Kind == "double" {
		msg = "There's a second router or NAT in front of yours (double NAT). Port forwarding and some games and calls can break; put one of the routers in bridge mode."
	}
	if n.Kind == "cgnat" && v6 != nil && v6.Reachable {
		msg += " IPv6 works here, which sidesteps it for apps that use IPv6."
	}
	return msg
}

func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	fast := fs.Bool("fast", false, "skip the speed test (about 15 s quicker)")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("doctor")
	ui.Open("Connection")
	g := ui.NewGroup()
	d, notes := runChecks(ctx, *fast, g)
	g.End()
	ui.Close()
	if ctx.Err() != nil {
		ui.Println("\n  " + ui.Dim("Interrupted."))
		return 130
	}

	// Verdict: the most serious finding leads, the rest follow quietly.
	worst, head, findings := doctorVerdict(d)
	// "Good for calls" beside a hard failure (dead DNS, say) would mislead:
	// the rows only show when nothing is broken outright.
	if len(d.Readiness) > 0 && worst != ui.Bad {
		ui.Println("")
		ui.Open("Good for")
		for _, row := range readinessRows(d.Readiness) {
			ui.Println(row)
		}
		ui.Close()
	}
	var extra []string
	var sqm *sqmSettings
	if d.Speed != nil {
		if sqm = sqmAdvice(*d.Speed); sqm != nil {
			extra = append(extra, sqm.line())
		}
	}
	if len(notes) > 0 {
		extra = append(extra, notes[0])
	}
	if *fast && d.online() {
		extra = append(extra, "Speed was skipped (--fast).")
	}
	printVerdict(worst, head, findings, extra...)
	ui.Println("")

	if *asJSON {
		printJSON(doctorReport{
			Gateway: d.Gateway, Internet: d.Internet, DNS: d.DNS, Readiness: d.Readiness,
			Verdict: verdict{worst.String(), head}, Findings: findingsJSON(findings),
			Wifi: d.Wifi, IPv6: d.IPv6, NAT: d.NAT, Speed: d.Speed, SQM: sqm, Fast: *fast, Notes: notes,
		})
	}
	return exitFor(worst)
}

func wifiDoctorRow(w probe.WifiInfo) string {
	st, _, note := wifiVerdict(w)
	if !w.Connected {
		return ui.Row("Wi-Fi", ui.Skip, "not in use", "–", ui.Dim(note))
	}
	ssid := w.SSID
	if ssid == "" {
		ssid = "(hidden name)"
	}
	metric := "–"
	if w.SignalDBm != 0 {
		metric = fmt.Sprintf("%d dBm", w.SignalDBm)
	}
	crowd := w.Crowding
	if crowd != "" {
		crowd += " channel"
	}
	return ui.Row("Wi-Fi", st, ssid, metric, ui.Dim(joinDot(probe.SignalQuality(w.SignalDBm), w.Band, chanLabel(w.Channel), crowd)))
}

func ipv6DoctorRow(v probe.IPv6Result) string {
	st, _ := ipv6Verdict(v)
	switch {
	case v.Reachable:
		pref := "IPv4 preferred"
		if v.Preferred {
			pref = "preferred"
		}
		return ui.Row("IPv6", st, "works", fmtMs(v.V6Ms), ui.Dim(pref))
	case v.Address != "":
		return ui.Row("IPv6", st, "broken", "–", ui.Dim("address "+v.Address+" but no route"))
	}
	return ui.Row("IPv6", ui.Skip, "not available", "–", ui.Dim("IPv4 only"))
}

func speedDoctorRow(s probe.SpeedResult) string {
	if s.Error != "" {
		return ui.Row("Speed", ui.Skip, "not measured", "–", ui.Dim(s.Error))
	}
	st, _ := speedVerdict(s)
	extra := "down / up"
	if s.Grade != "" {
		extra += fmt.Sprintf(" · bufferbloat %s (+%.0f ms)", s.Grade, s.BloatMs)
	}
	return ui.Row("Speed", st, fmt.Sprintf("%.0f / %.0f Mbps", s.DownMbps, s.UpMbps), "", ui.Dim(extra))
}

// runChecks measures everything Doctor looks at, drawing progress into g
// (which may be silent). It returns what it measured and any one-line notes.
func runChecks(ctx context.Context, fast bool, g *ui.Group) (doctorData, []string) {
	var d doctorData
	var notes []string
	var mu sync.Mutex // guards d and notes while checks run
	note := func(s string) {
		if s != "" {
			mu.Lock()
			notes = append(notes, s)
			mu.Unlock()
		}
	}
	const probes, gap = 10, 150 * time.Millisecond

	// finish resolves a row, unless Ctrl-C cut its check short: a cancelled
	// lookup would otherwise look like a failed one. Unresolved rows vanish.
	finish := func(row int, line string) {
		if ctx.Err() == nil {
			g.Finish(row, line)
		}
	}
	rGW, rWifi, rNet, rDNS, rV6, rNAT := g.Add("Gateway"), g.Add("Wi-Fi"), g.Add("Internet"), g.Add("DNS"), g.Add("IPv6"), g.Add("NAT")
	rSpeed := -1
	if !fast {
		rSpeed = g.Add("Speed")
		g.Progress(rSpeed, ui.Dim("waits for the other checks"))
	}

	gwIP, gwErr := probe.DefaultGateway()
	d.GatewayFound = gwErr == nil
	inetDone := make(chan struct{})
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}

	// Gateway: is the router reachable, and how good is the link to it?
	run(func() {
		if gwErr != nil {
			finish(rGW, ui.Row("Gateway", ui.Skip, "not found", "–", ui.Dim("couldn't detect your router")))
			return
		}
		var live []float64
		res := probe.PingBest(ctx, gwIP.String(), []int{80, 443, 53, 22}, probes, gap, func(ms float64) {
			live = append(live, ms)
			g.Progress(rGW, gwIP.String()+"  "+ui.Spark(live))
		})
		mu.Lock()
		d.Gateway = &res
		mu.Unlock()
		note(res.Note)
		st := pingStatus(res, 25, ui.Skip) // some routers ignore probes; not a failure by itself
		finish(rGW, pingRow("Gateway", st, res, "doesn't answer probes"))
	})

	// Wi-Fi: local, quick, and independent of everything else.
	run(func() {
		g.Progress(rWifi, "reading the adapter…")
		w := probe.ReadWifi(ctx)
		mu.Lock()
		d.Wifi = &w
		mu.Unlock()
		finish(rWifi, wifiDoctorRow(w))
	})

	// Internet: can we reach the outside world, and how stable is it?
	run(func() {
		defer close(inetDone)
		var res probe.PingResult
		for _, host := range []string{"1.1.1.1", "8.8.8.8"} {
			var live []float64
			res = probe.PingBest(ctx, host, []int{443, 53}, probes, gap, func(ms float64) {
				live = append(live, ms)
				g.Progress(rNet, host+"  "+ui.Spark(live))
			})
			if res.Received > 0 || ctx.Err() != nil {
				break
			}
		}
		mu.Lock()
		d.Internet = &res
		mu.Unlock()
		note(res.Note)
		finish(rNet, pingRow("Internet", pingStatus(res, 120, ui.Bad), res, ""))
	})
	online := func() bool {
		<-inetDone
		mu.Lock()
		defer mu.Unlock()
		return d.online()
	}
	skipped := func(row int, label string) {
		finish(row, ui.Row(label, ui.Skip, "skipped", "–", ui.Dim("no internet")))
	}

	// DNS: only meaningful once the internet is known to work.
	run(func() {
		g.Progress(rDNS, ui.Dim("waits for the internet check"))
		if !online() {
			skipped(rDNS, "DNS")
			return
		}
		g.Progress(rDNS, "checking resolvers…")
		rs := probe.BuildResolvers(gwIP)
		chans := startDNS(ctx, rs, probe.DefaultNames)
		results := make([]probe.DNSResult, len(rs))
		for i, ch := range chans {
			results[i] = <-ch
		}
		mu.Lock()
		d.DNS = results
		mu.Unlock()
		st, _, rowNote := dnsVerdict(results)
		sys := results[0]
		target, metric := sys.Label, "–"
		if sys.Addr != "" {
			target += " " + sys.Addr
		}
		if sys.Answered > 0 {
			metric = fmtMs(sys.MedianMs)
		}
		finish(rDNS, ui.Row("DNS", st, target, metric, ui.Dim(rowNote)))
	})

	// IPv6 runs alongside; it's only shown when the internet works.
	run(func() {
		g.Progress(rV6, "connecting over IPv6…")
		v := probe.CheckIPv6(ctx)
		if !online() {
			skipped(rV6, "IPv6")
			return
		}
		mu.Lock()
		d.IPv6 = &v
		mu.Unlock()
		finish(rV6, ipv6DoctorRow(v))
	})

	// NAT: the public address, then whether the ISP adds a NAT layer.
	run(func() {
		g.Progress(rNAT, ui.Dim("waits for the internet check"))
		if !online() {
			skipped(rNAT, "NAT")
			return
		}
		g.Progress(rNAT, "finding your public address…")
		pub, err := probe.PublicIP(ctx)
		if err != nil || gwErr != nil {
			finish(rNAT, ui.Row("NAT", ui.Skip, "unknown", "–", ui.Dim("couldn't find the public address or router")))
			return
		}
		g.Progress(rNAT, "asking "+gwIP.String()+"…")
		n := probe.DetectNAT(ctx, gwIP, pub, routeHops(gwIP))
		mu.Lock()
		d.NAT = &n
		mu.Unlock()
		st, label := natStatus(n)
		finish(rNAT, ui.Row("NAT", st, label, "", ui.Dim(joinDot(pub.String(), natRowNote(n)))))
	})

	wg.Wait()

	// Speed last, alone: its load would distort every other measurement.
	if rSpeed >= 0 {
		switch {
		case ctx.Err() != nil:
		case !d.online():
			skipped(rSpeed, "Speed")
		default:
			cfg := probe.DefaultSpeedConfig()
			cfg.Duration = doctorSpeedTime
			var spark []float64
			res := probe.RunSpeed(ctx, cfg, func(p probe.SpeedProgress) {
				if p.Phase == "latency" || p.Done {
					return
				}
				arrow := map[string]string{"download": "↓", "upload": "↑"}[p.Phase]
				spark = append(spark, p.Mbps)
				g.Progress(rSpeed, arrow+" "+fmt.Sprintf("%-10s", fmtMbps(p.Mbps))+ui.Trend(tail(spark, 24)))
			})
			d.Speed = &res
			finish(rSpeed, speedDoctorRow(res))
		}
	}
	readyFor(&d)
	return d, notes
}

// readyFor fills in what the connection is good for from what was measured.
func readyFor(d *doctorData) {
	if !d.online() {
		return
	}
	l := link{PingKnown: true, LatencyMs: d.Internet.AvgMs, JitterMs: d.Internet.JitterMs, LossKnown: true, LossPct: d.Internet.LossPct}
	if s := d.Speed; s != nil && s.Error == "" {
		l.DownMbps, l.UpMbps, l.LoadedMs = s.DownMbps, s.UpMbps, max(s.DownLoadedMs, s.UpLoadedMs)
	}
	d.Readiness = readiness(l)
}

// doctorVerdict is the headline and every finding behind it.
func doctorVerdict(d doctorData) (ui.Status, string, []finding) {
	findings := doctorFindings(d)
	healthy := "Your connection looks healthy."
	if line := readinessLine(d.Readiness); line != "" && !hasMsg(findings, line) {
		healthy += " " + line
	}
	st, head := lead(findings, healthy)
	return st, head, findings
}
