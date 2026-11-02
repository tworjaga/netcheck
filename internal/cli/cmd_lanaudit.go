package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/domain"
	"github.com/tworjaga/netcheck/internal/lanaudit"
	"github.com/tworjaga/netcheck/internal/ui"
)

// knownMACs is every device `netcheck devices` has seen, on any network
// (nil when there's no history at all).
func knownMACs() map[string]bool {
	p, err := devicesPath()
	if err != nil {
		return nil
	}
	s, err := loadDevices(p)
	if err != nil || len(s.Networks) == 0 {
		return nil
	}
	out := map[string]bool{}
	for _, n := range s.Networks {
		for _, d := range n.Devices {
			if d.MAC != "" {
				out[strings.ToLower(d.MAC)] = true
			}
		}
	}
	return out
}

// lanDeviceTable lists every device and what answered on it.
func lanDeviceTable(r lanaudit.Report, width int) ui.Table {
	wide := width >= 110
	tb := ui.Table{Headers: []string{"Address", "Device", "Open"}}
	if wide {
		tb.Headers = []string{"Address", "Device", "Maker", "Open"}
	}
	// The worst real finding on each device colours its row.
	risk := map[string]ui.Status{}
	for _, c := range r.Checks {
		st := checkStatus(c.Status)
		if c.Area != lanaudit.AreaDevices || (st != ui.Warn && st != ui.Bad) {
			continue
		}
		ip, _, _ := strings.Cut(c.Title, " ")
		ip = strings.TrimSuffix(ip, ":")
		risk[ip] = max(risk[ip], st)
	}
	for _, d := range r.Devices {
		name := d.Name
		switch {
		case d.Self:
			name = firstNonEmpty(name, "this machine") + ui.Dim(" (you)")
		case d.Gateway && name == "":
			name = "router"
		case d.Gateway:
			name += ui.Dim(" (router)")
		case name == "" && !wide && d.Vendor != "":
			name = ui.Dim(d.Vendor)
		case name == "":
			name = ui.Dim(firstNonEmpty(d.Kind, "unknown"))
		}
		var open []string
		for _, o := range d.Open {
			open = append(open, fmt.Sprintf("%d %s", o.Port, o.Name))
		}
		ports := strings.Join(open, ", ")
		if d.Self {
			ports = ui.Dim("see `netcheck listen`")
		}
		st := ui.OK
		if s, ok := risk[d.IP]; ok {
			st = s
		}
		// The "new" mark goes after shortening, so it's never cut off.
		mark := ""
		if !d.Known && !d.Self && d.MAC != "" && r.Checks != nil {
			mark = ui.Dim(" · new")
		}
		cells := []string{d.IP, ui.Cut(name, 22) + mark, ui.Cut(ports, max(20, width-48))}
		if wide {
			cells = []string{d.IP, ui.Cut(name, 30) + mark, ui.Cut(d.Vendor, 22), ui.Cut(ports, max(20, width-80))}
		}
		tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: cells})
	}
	return tb
}

func cmdLanaudit(args []string) int {
	fs := flag.NewFlagSet("lanaudit", flag.ExitOnError)
	common := adv.Register(fs)
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if len(pos) > 0 {
		fmt.Fprintln(os.Stderr, "netcheck lanaudit: takes no arguments; it audits the network this machine is on")
		return 2
	}
	rules, err := common.Rules()
	if err != nil {
		fmt.Fprintln(os.Stderr, "netcheck lanaudit: "+err.Error())
		return 2
	}
	known := knownMACs()
	ui.Title("lanaudit")
	t := ui.Begin("Auditing")
	t.Progress("Wi-Fi, router, UPnP and DHCP…")
	r := lanaudit.Audit(ctx, lanaudit.Options{Known: known, OnStatus: func(s string) { t.Progress(s + "…") }})
	t.Clear()
	if ctx.Err() != nil {
		return 130
	}
	st, msg, fixes := auditVerdict("Your network", r.Grade, r.Score, r.Checks, r.Error)
	if r.Error == "" {
		fixes = append(fixes, "lanaudit only looks at what answers: it tries no passwords and no exploits, and stays on this network.")
		if known == nil {
			fixes = append(fixes, "Run `netcheck devices` once, and later audits will point out devices that are new.")
		}
	}
	var broken []string
	if r.Error == "" {
		_, warn, bad := domain.Report{Checks: r.Checks}.Count()
		g, _ := adv.GradeValue(r.Grade)
		broken = adv.Broken(rules, adv.Default{Metric: "grade", Op: '<'}, map[string]float64{"grade": g, "score": float64(r.Score), "problems": float64(warn + bad), "bad": float64(bad)})
		ui.Open(fmt.Sprintf("%s · grade %s", r.Subnet, r.Grade))
		for _, l := range checkLines(lanaudit.Areas, r.Checks, ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
		ui.Println("")
		ui.Open(plural(len(r.Devices), "device", "devices"))
		for _, l := range lanDeviceTable(r, ui.PanelWidth()).Lines(ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
	}
	if !common.Raw {
		ui.Verdict(st, msg, append(fixes, broken...)...)
	}
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "lanaudit", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: r, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
