// Package lanaudit looks for risky settings and services on your own
// network: the Wi-Fi's encryption, the router (admin page, UPnP, DHCP),
// and a short list of ports on every device that answers. It only looks
// at what answers; it never tries passwords or exploits, and it never
// leaves the local network.
package lanaudit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/domain"
	"github.com/tworjaga/netcheck/internal/probe"
)

// Areas, in display order.
const (
	AreaWifi    = "Wi-Fi"
	AreaRouter  = "Router"
	AreaDevices = "Devices"
	AreaNew     = "New devices"
)

// Areas lists the audit's areas in display order.
var Areas = []string{AreaWifi, AreaRouter, AreaDevices, AreaNew}

// risky is what an open port on a device means.
type risky struct {
	name string
	st   domain.Status
	why  string
	fix  string
}

// Ports are the services looked for on every device: few enough to stay
// gentle, the ones that matter on a home or office network.
var Ports = map[int]risky{
	23:    {"Telnet", domain.Bad, "sends passwords in the clear, and is a favourite way in for botnets", "Turn Telnet off in the device's settings; use SSH or the web page instead."},
	21:    {"FTP", domain.Warn, "sends passwords in the clear", "Turn FTP off, or use SFTP / FTPS if the device offers them."},
	2375:  {"Docker API", domain.Bad, "whoever reaches it controls the machine", "Bind the Docker API to localhost, or use TLS on 2376."},
	6379:  {"Redis", domain.Bad, "has no password by default", "Bind Redis to localhost or set requirepass, and keep it off the network."},
	27017: {"MongoDB", domain.Bad, "often runs without a login", "Turn on authorization and bind it to localhost."},
	1883:  {"MQTT", domain.Warn, "smart-home messages, unencrypted and often without a login", "Require a login on the MQTT broker, or use MQTT over TLS on 8883."},
	5900:  {"VNC", domain.Warn, "remote control, often with a weak password or none", "Set a strong VNC password, or reach it through SSH or a VPN."},
	3389:  {"Remote Desktop", domain.Info, "remote control of a Windows PC", "Fine on a home network if you use it; make sure the account has a strong password."},
	3306:  {"MySQL", domain.Warn, "a database open to the whole network", "Bind the database to localhost unless other machines need it."},
	5432:  {"PostgreSQL", domain.Warn, "a database open to the whole network", "Bind the database to localhost unless other machines need it."},
	554:   {"camera stream (RTSP)", domain.Info, "a live video stream", "Check that the camera's stream needs a password, and that the camera's firmware is current."},
	445:   {"file sharing (SMB)", domain.Info, "shared folders", "Fine if you share files on purpose; check that shares need a password."},
	9100:  {"printer (raw)", domain.Info, "anyone on the network can print", ""},
	80:    {"web page (HTTP)", domain.Info, "a web interface without encryption", ""},
	8080:  {"web page (HTTP, 8080)", domain.Info, "a web interface without encryption", ""},
	22:    {"SSH", domain.Info, "remote login", ""},
	443:   {"web page (HTTPS)", domain.OK, "", ""},
}

// Finding on one device.
type Open struct {
	Port int    `json:"port"`
	Name string `json:"name"`
}

// DeviceReport is one device and what answered on it.
type DeviceReport struct {
	probe.Device
	Open  []Open `json:"open"`
	Known bool   `json:"known"` // seen by `netcheck devices` before
}

// Report is the audit.
type Report struct {
	Subnet  string              `json:"subnet"`
	Gateway string              `json:"gateway"`
	Wifi    *probe.WifiInfo     `json:"wifi,omitempty"`
	Devices []DeviceReport      `json:"devices"`
	UPnP    *bool               `json:"upnp,omitempty"`
	Mapped  []probe.PortMapping `json:"port_forwards,omitempty"`
	DHCP    *probe.DHCPResult   `json:"dhcp,omitempty"`
	Checks  []domain.Check      `json:"checks"`
	Score   int                 `json:"score"`
	Grade   string              `json:"grade"`
	Took    time.Duration       `json:"took_ns"`
	Error   string              `json:"error,omitempty"`
}

// Options shape an audit.
type Options struct {
	Known    map[string]bool // MAC addresses seen before (nil: no history)
	OnStatus func(string)
}

// Test seams.
var (
	readWifi = probe.ReadWifi
	gateway  = probe.DefaultGateway
	localIP  = probe.LocalIP
	subnetOf = probe.LocalSubnet
	discover = probe.DiscoverDevices
	mappings = probe.PortMappings
	findDHCP = probe.FindDHCPServers
	dialPort = func(ctx context.Context, addr string) bool {
		d := net.Dialer{Timeout: 800 * time.Millisecond}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			c.Close()
		}
		return err == nil
	}
	// adminRedirects says whether http://ip/ sends visitors to https.
	adminRedirects = func(ctx context.Context, ip string) bool {
		c := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+ip+"/", nil)
		res, err := c.Do(req)
		if err != nil {
			return false
		}
		res.Body.Close()
		return res.StatusCode >= 300 && res.StatusCode < 400 && strings.HasPrefix(strings.ToLower(res.Header.Get("Location")), "https://")
	}
)

// WifiCheck judges the encryption of the network this machine uses.
func WifiCheck(w probe.WifiInfo) []domain.Check {
	if !w.Connected {
		return nil
	}
	sec := strings.ToUpper(w.Security)
	cipher := strings.ToUpper(w.Cipher)
	add := func(st domain.Status, title, detail, fix string) []domain.Check {
		return []domain.Check{{Area: AreaWifi, Status: st, Title: title, Detail: detail, Fix: fix}}
	}
	name := w.SSID
	if name == "" {
		name = "this Wi-Fi"
	}
	detail := strings.TrimSpace(w.Security + " " + w.Cipher)
	switch {
	case sec == "":
		return add(domain.Info, "Couldn't read the encryption of "+name, "", "")
	case strings.Contains(sec, "OPEN") || sec == "NONE" || strings.Contains(sec, "OFFEN") || strings.Contains(sec, "OUVERT") || strings.Contains(sec, "ABIERT"):
		return add(domain.Bad, name+" is open: no password, no encryption", detail,
			"Turn on WPA2 or WPA3 in the router's Wi-Fi settings; anyone nearby can read the traffic and join.")
	case strings.Contains(sec, "WEP"):
		return add(domain.Bad, name+" uses WEP", detail+" · broken since 2001; cracked in minutes",
			"Switch the router to WPA2-Personal (AES) or WPA3.")
	case strings.Contains(sec, "WPA3") || strings.Contains(sec, "SAE") || strings.Contains(sec, "OWE"):
		return add(domain.OK, name+" uses WPA3", detail, "")
	case strings.Contains(sec, "WPA2") || strings.Contains(sec, "RSN"):
		if strings.Contains(cipher, "TKIP") {
			return add(domain.Warn, name+" uses WPA2 with the old TKIP cipher", detail,
				"Set the router's Wi-Fi encryption to AES (CCMP) only; TKIP is weak and limits speed to 54 Mbit/s.")
		}
		return add(domain.OK, name+" uses WPA2", detail, "")
	case strings.Contains(sec, "WPA"):
		return add(domain.Warn, name+" uses the first WPA", detail+" · outdated",
			"Switch the router to WPA2-Personal (AES) or WPA3.")
	}
	return add(domain.Info, name+": "+detail, "", "")
}

// shortName is how a device reads in a sentence.
func shortName(d probe.Device) string {
	parts := []string{d.IP}
	switch {
	case d.Name != "":
		parts = append(parts, d.Name)
	case d.Vendor != "":
		parts = append(parts, d.Vendor)
	}
	if d.Gateway {
		parts = append(parts, "router")
	}
	if len(parts) == 1 {
		return d.IP
	}
	return parts[0] + " (" + strings.Join(parts[1:], ", ") + ")"
}

// scanPorts checks Ports on every device but this machine, 64 at a time.
func scanPorts(ctx context.Context, devs []probe.Device) map[string][]Open {
	ports := make([]int, 0, len(Ports))
	for p := range Ports {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	out := map[string][]Open{}
	var mu sync.Mutex
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for _, d := range devs {
		if d.Self {
			continue
		}
		for _, p := range ports {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if dialPort(ctx, net.JoinHostPort(d.IP, strconv.Itoa(p))) {
					mu.Lock()
					out[d.IP] = append(out[d.IP], Open{Port: p, Name: Ports[p].name})
					mu.Unlock()
				}
			}()
		}
	}
	wg.Wait()
	for ip := range out {
		sort.Slice(out[ip], func(i, j int) bool { return out[ip][i].Port < out[ip][j].Port })
	}
	return out
}

// Audit runs everything.
func Audit(ctx context.Context, o Options) Report {
	start := time.Now()
	var r Report
	defer func() { r.Took = time.Since(start) }()
	status := func(s string) {
		if o.OnStatus != nil {
			o.OnStatus(s)
		}
	}
	gw, err := gateway()
	if err != nil {
		r.Error = "no router found; is this machine on a network?"
		return r
	}
	r.Gateway = gw.String()
	me := localIP()
	subnet, err := subnetOf(me)
	if err != nil {
		r.Error = "couldn't tell which network this is: " + err.Error()
		return r
	}
	if !subnet.IP.IsPrivate() {
		r.Error = "this network (" + subnet.String() + ") uses public addresses; lanaudit only looks at private networks"
		return r
	}
	r.Subnet = subnet.String()

	var wifi probe.WifiInfo
	var maps []probe.PortMapping
	var mapErr error
	var dhcp probe.DHCPResult
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); wifi = readWifi(ctx) }()
	go func() {
		defer wg.Done()
		// Routers don't always answer the UPnP search the first time;
		// "off" needs two silences.
		maps, mapErr = mappings(ctx, gw)
		if errors.Is(mapErr, probe.ErrNoUPnP) && ctx.Err() == nil {
			maps, mapErr = mappings(ctx, gw)
		}
	}()
	go func() { defer wg.Done(); dhcp = findDHCP(ctx, 3*time.Second) }()
	status("finding the devices on " + subnet.String())
	res := discover(ctx, me, gw, subnet, probe.ScanOptions{MDNSWait: 2 * time.Second, SSDPWait: 2 * time.Second})
	status(fmt.Sprintf("checking %d devices for risky services", len(res.Devices)))
	open := scanPorts(ctx, res.Devices)
	wg.Wait()
	if wifi.Connected {
		r.Wifi = &wifi
	}
	r.DHCP = &dhcp

	for _, d := range res.Devices {
		dr := DeviceReport{Device: d, Open: open[d.IP]}
		if o.Known != nil && d.MAC != "" {
			dr.Known = o.Known[strings.ToLower(d.MAC)]
		}
		r.Devices = append(r.Devices, dr)
	}
	sort.Slice(r.Devices, func(i, j int) bool { return ipLess(r.Devices[i].IP, r.Devices[j].IP) })

	r.Checks = append(r.Checks, WifiCheck(wifi)...)
	r.Checks = append(r.Checks, RouterChecks(ctx, gw.String(), open[gw.String()], maps, mapErr, dhcp)...)
	r.Checks = append(r.Checks, DeviceChecks(r.Devices)...)
	if o.Known != nil {
		r.Checks = append(r.Checks, NewDeviceChecks(r.Devices)...)
	}
	if mapErr == nil {
		on := true
		r.UPnP, r.Mapped = &on, maps
	} else if errors.Is(mapErr, probe.ErrNoUPnP) {
		off := false
		r.UPnP = &off
	}
	order := map[string]int{}
	for i, a := range Areas {
		order[a] = i
	}
	sort.SliceStable(r.Checks, func(i, j int) bool { return order[r.Checks[i].Area] < order[r.Checks[j].Area] })
	best := false
	for _, c := range r.Checks {
		best = best || c.Area == AreaWifi && c.Status == domain.OK && strings.Contains(c.Title, "WPA3")
	}
	r.Score, r.Grade = domain.Grade(r.Checks, best)
	return r
}

func ipLess(a, b string) bool {
	x, y := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if x == nil || y == nil {
		return a < b
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return false
}

// RouterChecks: the admin page, UPnP and its forwards, and DHCP servers.
func RouterChecks(ctx context.Context, gw string, open []Open, maps []probe.PortMapping, mapErr error, dhcp probe.DHCPResult) []domain.Check {
	var cs []domain.Check
	add := func(st domain.Status, title, detail, fix string) {
		cs = append(cs, domain.Check{Area: AreaRouter, Status: st, Title: title, Detail: detail, Fix: fix})
	}
	has := map[int]bool{}
	for _, o := range open {
		has[o.Port] = true
	}
	switch {
	case has[80] && !has[443] && !adminRedirects(ctx, gw):
		add(domain.Warn, "The router's admin page is only on plain HTTP", "http://"+gw,
			"Anyone on the network who watches the traffic can read the admin password as you type it. Turn on HTTPS for the admin page if the router offers it, and log in only from a cable or trusted Wi-Fi.")
	case has[80] || has[443]:
		add(domain.OK, "The router's admin page uses HTTPS", "https://"+gw, "")
	}
	if has[23] {
		add(domain.Bad, "The router answers Telnet", gw+":23", "Turn Telnet off in the router's settings; it sends the admin password in the clear.")
	}
	switch {
	case mapErr == nil && len(maps) == 0:
		add(domain.Info, "UPnP is on, with no ports forwarded", "",
			"UPnP lets any device on the network open ports to the internet without asking. Turn it off in the router if nothing (games, consoles, calls) needs it.")
	case mapErr == nil:
		var who []string
		for _, m := range maps {
			d := fmt.Sprintf("%s %d to %s:%d", m.Protocol, m.ExternalPort, m.Client, m.InternalPort)
			if m.Description != "" {
				d += " (" + m.Description + ")"
			}
			who = append(who, d)
		}
		add(domain.Warn, fmt.Sprintf("UPnP is on, and devices have opened %d to the internet", len(maps)), strings.Join(who, "; "),
			"Check each one is wanted (`netcheck upnp` lists them). Turn UPnP off in the router if you don't need it; then forward only what you choose.")
	case errors.Is(mapErr, probe.ErrNoUPnP):
		add(domain.OK, "UPnP is off", "devices can't open ports to the internet on their own", "")
	}
	switch {
	case dhcp.Unavailable != "":
		add(domain.Info, "DHCP servers not checked", dhcp.Unavailable, "")
	case len(dhcp.Servers) > 1:
		var ids []string
		for _, s := range dhcp.Servers {
			ids = append(ids, s.ServerID)
		}
		add(domain.Bad, fmt.Sprintf("%d DHCP servers answer", len(dhcp.Servers)), strings.Join(ids, ", "),
			"Only one should hand out addresses. A second one is a misconfigured device (a second router, say) or someone redirecting traffic; find it with `netcheck dhcp` and switch its DHCP off.")
	case len(dhcp.Servers) == 1:
		s := dhcp.Servers[0]
		d := "DNS " + strings.Join(s.DNS, ", ")
		if len(s.DNS) == 0 {
			d = ""
		}
		if s.ServerID != gw {
			add(domain.Info, "Addresses come from "+s.ServerID+", not the router ("+gw+")", d,
				"Fine if that's on purpose: a second router or mesh system, a Pi-hole or a server running DHCP. If you don't know the device, find out what it is.")
		} else {
			add(domain.OK, "One DHCP server, the router", d, "")
		}
	}
	return cs
}

// DeviceChecks: what answered on each device.
func DeviceChecks(devs []DeviceReport) []domain.Check {
	var cs []domain.Check
	clean := 0
	for _, d := range devs {
		if d.Self {
			continue
		}
		worst := 0
		for _, o := range d.Open {
			r := Ports[o.Port]
			if d.Gateway && (o.Port == 80 || o.Port == 443 || o.Port == 23 || o.Port == 8080) {
				continue // the router's own section covers these
			}
			if r.st == domain.OK || r.why == "" || r.st == domain.Info && r.fix == "" {
				continue // shown in the device list, not worth a finding
			}
			worst++
			cs = append(cs, domain.Check{Area: AreaDevices, Status: r.st, Title: fmt.Sprintf("%s: %s", shortName(d.Device), r.name),
				Detail: fmt.Sprintf("port %d · %s", o.Port, r.why), Fix: r.fix})
		}
		if worst == 0 {
			clean++
		}
	}
	others := 0
	for _, d := range devs {
		if !d.Self {
			others++
		}
	}
	if others > 0 {
		cs = append(cs, domain.Check{Area: AreaDevices, Status: domain.OK, Title: fmt.Sprintf("%d of %s show nothing risky", clean, plural(others, "device", "devices"))})
	}
	return cs
}

// NewDeviceChecks lists devices `netcheck devices` hasn't seen before.
func NewDeviceChecks(devs []DeviceReport) []domain.Check {
	var fresh []string
	for _, d := range devs {
		if d.Self || d.Known || d.MAC == "" {
			continue
		}
		fresh = append(fresh, shortName(d.Device))
	}
	if len(fresh) == 0 {
		return []domain.Check{{Area: AreaNew, Status: domain.OK, Title: "Every device has been seen before"}}
	}
	return []domain.Check{{Area: AreaNew, Status: domain.Info, Title: plural(len(fresh), "device netcheck hasn't seen before", "devices netcheck hasn't seen before"),
		Detail: strings.Join(fresh, "; "), Fix: "Check you know them; `netcheck devices` remembers them from then on."}}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
