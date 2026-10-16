package cli

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
	"github.com/tworjaga/netcheck/internal/wol"
)

// wakeTarget finds the MAC address to wake: given directly, or a device
// `netcheck devices` has seen, by name or address.
func wakeTarget(arg string, store *deviceStore) (net.HardwareAddr, string, string, error) {
	if mac, err := wol.ParseMAC(arg); err == nil {
		ip := ""
		if store != nil {
			for _, n := range store.Networks {
				for _, d := range n.Devices {
					if strings.EqualFold(d.MAC, mac.String()) {
						ip = d.IP
					}
				}
			}
		}
		return mac, "", ip, nil
	}
	if store == nil {
		return nil, "", "", fmt.Errorf("%q isn't a MAC address (like 00:11:22:33:44:55)", arg)
	}
	var matches []*knownDevice
	for _, n := range store.Networks {
		for _, d := range n.Devices {
			if d.MAC != "" && (strings.EqualFold(d.Name, arg) || d.IP == arg || strings.Contains(strings.ToLower(d.Name), strings.ToLower(arg))) {
				matches = append(matches, d)
			}
		}
	}
	switch len(matches) {
	case 0:
		return nil, "", "", fmt.Errorf("%q isn't a MAC address, and `netcheck devices` hasn't seen a device by that name or address", arg)
	case 1:
		mac, err := wol.ParseMAC(matches[0].MAC)
		return mac, firstNonEmpty(matches[0].Name, matches[0].IP), matches[0].IP, err
	}
	var names []string
	for _, d := range matches {
		names = append(names, firstNonEmpty(d.Name, d.IP)+" ("+d.MAC+")")
	}
	sort.Strings(names)
	return nil, "", "", fmt.Errorf("%q matches several devices: %s; give the MAC address", arg, strings.Join(names, ", "))
}

// wakeWait pings ip until it answers or the time runs out.
var wakeWait = func(ctx context.Context, ip string, d time.Duration) (time.Duration, bool) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	for ctx.Err() == nil {
		r := probe.PingBest(ctx, ip, []int{445, 22, 3389, 80}, 1, time.Second, nil)
		if r.Received > 0 {
			return time.Since(start), true
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	return time.Since(start), false
}

func cmdWake(args []string) int {
	fs := flag.NewFlagSet("wake", flag.ExitOnError)
	common := adv.Register(fs)
	to := fs.String("ip", "", "send to this address instead (a directed broadcast like 192.168.0.255, or a host across a VPN)")
	port := fs.Int("p", 9, "UDP port (9 or 7)")
	wait := fs.Duration("wait", 0, "then wait up to this long for the device to answer, e.g. 2m")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck wake: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck wake <MAC address | device name> [--wait 2m] [--ip 192.168.0.255]")
		return 2
	}
	if len(pos) != 1 {
		return usage("give the MAC address of the machine to wake, or its name from `netcheck devices`")
	}
	var store *deviceStore
	if p, err := devicesPath(); err == nil {
		store, _ = loadDevices(p)
	}
	mac, name, ip, err := wakeTarget(pos[0], store)
	if err != nil {
		return usage(err.Error())
	}
	targets := wol.Broadcasts(wol.LocalNets())
	if *to != "" {
		if net.ParseIP(*to) == nil {
			return usage(fmt.Sprintf("--ip %q isn't an address", *to))
		}
		targets = []string{*to}
	}
	who := mac.String()
	if name != "" {
		who = name + " (" + mac.String() + ")"
	}
	ui.Title("wake")
	sent, errs := wol.Wake(mac, targets, *port)
	if len(sent) == 0 {
		var e []string
		for _, x := range errs {
			e = append(e, x.Error())
		}
		ui.Verdict(ui.Bad, "Couldn't send the wake-up packet: "+strings.Join(e, "; ")+".")
		ui.Println("")
		return 1
	}
	st, msg := ui.OK, fmt.Sprintf("Sent the wake-up packet for %s to %s.", who, strings.Join(sent, ", "))
	notes := []string{"Wake-on-LAN has no answer: whether it worked shows only when the machine comes up. It must be enabled in its BIOS/UEFI and network adapter settings, and reach it over the local network (or a router that forwards it)."}
	var waited time.Duration
	up := false
	if *wait > 0 {
		if ip == "" {
			notes = append(notes, "--wait needs the device's address, and `netcheck devices` hasn't seen this MAC; check by hand.")
		} else {
			t := ui.Begin("Waiting")
			t.Progress(fmt.Sprintf("for %s to answer (up to %s)…", ip, *wait))
			waited, up = wakeWait(ctx, ip, *wait)
			t.Clear()
			if ctx.Err() != nil {
				return 130
			}
			if up {
				msg += fmt.Sprintf(" It answered at %s after %s.", ip, fmtDur(waited.Round(time.Second)))
				notes = notes[:0]
			} else {
				st = ui.Warn
				msg += fmt.Sprintf(" It didn't answer at %s within %s.", ip, *wait)
				notes = append(notes, "If it doesn't wake at all, check that Wake-on-LAN is on in the BIOS and the adapter (Windows: Device Manager > adapter > Power Management and Advanced > Wake on Magic Packet), and that it was shut down, not unplugged.")
			}
		}
	}
	ui.Verdict(st, msg, notes...)
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "wake", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg},
			Data: map[string]any{"mac": mac.String(), "name": name, "sent_to": sent, "port": *port, "waited_ns": waited, "up": up}}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), nil)
}
