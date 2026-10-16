package cli

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/tworjaga/netcheck/internal/sockets"
	"github.com/tworjaga/netcheck/internal/tracex"
	"github.com/tworjaga/netcheck/internal/ui"
)

func TestListenGroupAndFindings(t *testing.T) {
	ss := []sockets.Socket{
		{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 445, State: "LISTEN", PID: 4, Process: "System"},
		{Proto: "tcp", LocalIP: "::", LocalPort: 445, State: "LISTEN", PID: 4, Process: "System"},
		{Proto: "udp", LocalIP: "192.168.0.200", LocalPort: 137, State: "BOUND", PID: 4, Process: "System"},
		{Proto: "udp", LocalIP: "172.21.16.1", LocalPort: 137, State: "BOUND", PID: 4, Process: "System"},
		{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 6379, State: "LISTEN", PID: 9, Process: "redis-server"},
		{Proto: "tcp", LocalIP: "127.0.0.1", LocalPort: 5432, State: "LISTEN", PID: 10, Process: "postgres"},
		{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 3000, State: "LISTEN", PID: 11, Process: "node"},
		{Proto: "udp", LocalIP: "0.0.0.0", LocalPort: 61234, State: "BOUND", PID: 12, Process: "opera.exe"},
		{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 49664, State: "LISTEN", PID: 13, Process: "lsass.exe"},
		{Proto: "tcp", LocalIP: "127.0.0.1", LocalPort: 49671, State: "LISTEN", PID: 14, Process: "jhi_service.exe"},
	}
	ls := group(ss, false)
	if len(ls) != 7 {
		t.Fatalf("grouped: %+v", ls)
	}
	byPort := map[int]listener{}
	for _, l := range ls {
		byPort[l.Port] = l
	}
	if l := byPort[445]; l.Scope != "network" || len(l.Addrs) != 2 || l.Service != "SMB file sharing" {
		t.Errorf("445: %+v", l)
	}
	if l := byPort[137]; l.Scope != "interface" || !strings.Contains(reach(l), "192.168.0.200") {
		t.Errorf("137: %+v %s", l, reach(l))
	}
	if byPort[49664].Service != "Windows RPC" || byPort[49671].Service != "" {
		t.Errorf("RPC only for Windows' own processes: %+v %+v", byPort[49664], byPort[49671])
	}
	if _, ok := byPort[61234]; ok {
		t.Error("ephemeral UDP is left out by default")
	}
	if ls[len(ls)-1].Scope != "local" || ls[0].Scope != "network" {
		t.Error("network first, local last")
	}
	if len(group(ss, true)) != 8 {
		t.Error("--all keeps ephemeral UDP")
	}
	st, msg, notes := listenVerdict(ls, false)
	all := strings.Join(notes, " ")
	if st != ui.Bad || !strings.Contains(msg, "6 programs listen on 7 ports; 5 open to the network") {
		t.Errorf("%v %q", st, msg)
	}
	if !strings.Contains(all, "Redis (TCP 6379, redis-server)") || strings.Contains(all, "PostgreSQL") || !strings.Contains(all, "A development server (node)") {
		t.Errorf("findings: %v", notes)
	}
	if st, _, notes := listenVerdict(group(ss[:1], false), true); st != ui.OK || !strings.Contains(strings.Join(notes, " "), "other users") {
		t.Errorf("partial: %v %v", st, notes)
	}
	for _, l := range listenTable(ls).Lines(78) {
		if ui.VisWidth(l) > 78 {
			t.Errorf("too wide: %q", l)
		}
	}
}

func TestConns(t *testing.T) {
	old, oldAddr, oldOwner := listSockets, connAddr, connOwner
	defer func() { listSockets, connAddr, connOwner = old, oldAddr, oldOwner }()
	connAddr = func(_ context.Context, ip string) ([]string, error) {
		if ip == "160.79.104.10" {
			return []string{"api.example.test."}, nil
		}
		return nil, nil
	}
	connOwner = func(_ context.Context, ip net.IP) tracex.Owner {
		return tracex.Owner{ASN: 64500, Name: "EXAMPLE - Example Networks, US"}
	}
	var cs []conn
	add := func(proc, ip string, port int, state string) {
		cs = append(cs, conn{Socket: sockets.Socket{Proto: "tcp", Process: proc, RemoteIP: ip, RemotePort: port, State: state}})
	}
	for i := 0; i < 3; i++ {
		add("claude.exe", "160.79.104.10", 443, "ESTABLISHED")
	}
	add("app.exe", "192.168.0.38", 8009, "ESTABLISHED")
	for i := 0; i < 12; i++ {
		add("leaky.exe", "203.0.113.5", 8080, "CLOSE_WAIT")
	}
	add("stuck.exe", "198.51.100.7", 25, "SYN_SENT")
	nameRemotes(context.Background(), cs)
	if cs[0].Host != "api.example.test" || cs[0].Owner != "Example Networks" || cs[3].Owner != "local network" {
		t.Errorf("names: %+v %+v", cs[0], cs[3])
	}
	f := fold(cs)
	if len(f) != 4 || f[0].Count != 3 || f[2].Count != 12 {
		t.Errorf("fold: %+v", f)
	}
	st, msg, notes := connsVerdict(cs, false)
	all := strings.Join(notes, " ")
	if st != ui.Warn || msg != "17 connections from 4 programs to 2 networks; the most from leaky (12)." {
		t.Errorf("%v %q", st, msg)
	}
	if !strings.Contains(all, "leaky.exe holds 12 connections") || !strings.Contains(all, "stuck.exe is trying to reach 198.51.100.7:25") {
		t.Errorf("notes: %v", notes)
	}
	for _, l := range connsTable(f, 78).Lines(78) {
		if ui.VisWidth(l) > 78 {
			t.Errorf("too wide: %q", l)
		}
	}
	if st, msg, _ := connsVerdict(nil, false); st != ui.OK || msg != "No open connections." {
		t.Errorf("none: %q", msg)
	}
}
