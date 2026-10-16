package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// deviceLine formats one device as aligned columns: address, name, details.
func deviceLine(d probe.Device) string {
	name := d.Name
	if len(name) > 26 {
		name = name[:25] + "…"
	}
	if name == "" {
		name = "–"
	}
	var detail []string
	switch {
	case d.Self:
		detail = append(detail, "this computer")
	case d.Kind != "":
		detail = append(detail, d.Kind)
	}
	switch {
	case d.Vendor != "":
		detail = append(detail, d.Vendor)
	case d.RandomMAC:
		detail = append(detail, "private address")
	}
	return "  " + ui.Pad(d.IP, 17) + ui.Pad(name, 28) + ui.Dim(joinDot(detail...))
}

type devicesReport struct {
	probe.DevicesResult
	New        []string `json:"new,omitempty"`         // addresses not seen on this network before
	KnownSince string   `json:"known_since,omitempty"` // the previous scan, RFC 3339
}

func cmdDevices(args []string) int {
	fs := flag.NewFlagSet("devices", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	noSave := fs.Bool("no-save", false, "don't remember this scan or compare it with the last one")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ui.Title("devices")
	local := probe.LocalIP()
	subnet, err := probe.LocalSubnet(local)
	if err != nil {
		ui.Println("  " + ui.Alert("Couldn't find your local network.") + ui.Dim(" Are you connected?") + "\n")
		if *asJSON {
			printJSON(devicesReport{DevicesResult: probe.DevicesResult{Error: err.Error()}})
		}
		return 1
	}
	gw, _ := probe.DefaultGateway()

	t := ui.Begin("Scanning")
	phases := map[string]string{"sweeping": "pinging " + subnet.String(), "arp": "reading the ARP table", "names": "looking up names"}
	count := 0
	res := probe.DiscoverDevices(ctx, local, gw, subnet, probe.ScanOptions{
		OnStatus: func(p string) { t.Progress(fmt.Sprintf("%s · %d found", phases[p], count)) },
		OnFound:  func(n int) { count = n; t.Progress(fmt.Sprintf("%d found", n)) },
	})
	t.Clear()
	if ctx.Err() != nil {
		ui.Println("  " + ui.Dim("Interrupted.") + "\n")
		return 130
	}
	rep := devicesReport{DevicesResult: res}
	var diff *deviceDiff
	if !*noSave && len(res.Devices) > 0 {
		diff = rememberDevices(res.Devices, subnet.String(), time.Now())
	}
	if ui.Framed() {
		ui.Open(res.Summary())
	} else {
		ui.Println("  " + res.Summary() + "\n")
	}
	for _, d := range res.Devices {
		line := deviceLine(d)
		if diff != nil && diff.New[deviceKey(d)] {
			line += "  " + ui.Warn.Paint("new")
			rep.New = append(rep.New, d.IP)
		}
		ui.Println(line)
	}
	ui.Close()
	if diff != nil {
		if !diff.Since.IsZero() {
			rep.KnownSince = diff.Since.Format(time.RFC3339)
		}
		if l := diffLine(*diff, res.Devices); l != "" {
			ui.Println("\n  " + l)
		}
	}
	if res.Note != "" {
		ui.Println("\n  " + ui.Dim(res.Note))
	}
	ui.Println("")
	if *asJSON {
		printJSON(rep)
	}
	return 0
}

// rememberDevices compares a scan with the devices file and records it. A
// file that can't be read or written only costs the comparison.
func rememberDevices(devs []probe.Device, subnet string, now time.Time) *deviceDiff {
	path, err := devicesPath()
	if err != nil {
		return nil
	}
	s, err := loadDevices(path)
	if err != nil {
		return nil // unreadable: leave it alone rather than overwrite it
	}
	diff := s.remember(networkKey(devs, subnet), subnet, devs, now)
	if s.save(path) != nil {
		return nil
	}
	return &diff
}

// diffLine says what changed since the last scan of this network.
func diffLine(diff deviceDiff, devs []probe.Device) string {
	if diff.First {
		return ui.Dim(fmt.Sprintf("Remembered %s on this network. Next time, new ones are marked.", plural(len(devs), "device", "devices")))
	}
	since := diff.Since.Format("Mon Jan 2 15:04")
	if len(diff.New) == 0 {
		return ui.Dim("No new devices since " + since + ".")
	}
	var ips []string
	random := false
	for _, d := range devs {
		if diff.New[deviceKey(d)] {
			ips = append(ips, d.IP)
			random = random || d.RandomMAC
		}
	}
	msg := ui.Warn.Paint(fmt.Sprintf("%s since %s: %s.", plural(len(ips), "new device", "new devices"), since, strings.Join(ips, ", ")))
	if random {
		msg += "\n  " + ui.Dim("Phones and laptops with private Wi-Fi addresses can look new when they change address.")
	}
	return msg
}
