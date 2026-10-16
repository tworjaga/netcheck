package sockets

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: C800A8C0:D431 22D8B8AC:01BB 01 00000000:00000000 02:000A7B4C 00000000  1000        0 23456 2 0000000000000000 20 4 30 10 -1`
	ss, inodes, err := ParseProcNet(tcp, "tcp")
	if err != nil || len(ss) != 2 || strings.Join(inodes, ",") != "12345,23456" {
		t.Fatalf("%v %v %v", ss, inodes, err)
	}
	if s := ss[0]; s.LocalIP != "127.0.0.1" || s.LocalPort != 8080 || s.State != "LISTEN" || s.RemoteIP != "" || s.Scope() != "local" {
		t.Errorf("listener: %+v", s)
	}
	if s := ss[1]; s.LocalIP != "192.168.0.200" || s.RemoteIP != "172.184.216.34" || s.RemotePort != 443 || s.State != "ESTABLISHED" {
		t.Errorf("connection: %+v", s)
	}
	tcp6 := `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777 1
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 778 1`
	ss, _, err = ParseProcNet(tcp6, "tcp")
	if err != nil || ss[0].LocalIP != "::" || ss[0].LocalPort != 22 || ss[0].Scope() != "all" || ss[1].LocalIP != "::1" || ss[1].LocalPort != 631 {
		t.Errorf("tcp6: %+v %v", ss, err)
	}
	udp := `  sl  local_address rem_address   st
  10: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 999 2`
	ss, _, _ = ParseProcNet(udp, "udp")
	if ss[0].State != "BOUND" || ss[0].LocalPort != 68 || !ss[0].Listening() {
		t.Errorf("udp: %+v", ss[0])
	}
	if _, _, err := ParseProcNet("header\n 0: zz:1 00000000:0000 0A a b c d e 1", "tcp"); err == nil {
		t.Error("bad hex")
	}
}

func TestParseLsof(t *testing.T) {
	out := "p123\ncnginx\nf6\nPTCP\nn*:80\nTST=LISTEN\nf7\nPTCP\nn[::1]:8080\nTST=LISTEN\n" +
		"p456\ncFirefox\nf30\nPTCP\nn192.168.1.5:50000->93.184.216.34:443\nTST=ESTABLISHED\nf31\nPUDP\nn*:5353\n"
	ss := ParseLsof(out)
	if len(ss) != 4 {
		t.Fatalf("%+v", ss)
	}
	if s := ss[0]; s.Process != "nginx" || s.PID != 123 || s.LocalIP != "0.0.0.0" || s.LocalPort != 80 || s.State != "LISTEN" || s.Scope() != "all" {
		t.Errorf("nginx: %+v", s)
	}
	if s := ss[1]; s.LocalIP != "::1" || s.LocalPort != 8080 || s.Scope() != "local" {
		t.Errorf("v6: %+v", s)
	}
	if s := ss[2]; s.Process != "Firefox" || s.RemoteIP != "93.184.216.34" || s.RemotePort != 443 || s.State != "ESTABLISHED" {
		t.Errorf("conn: %+v", s)
	}
	if s := ss[3]; s.Proto != "udp" || s.State != "BOUND" || s.LocalPort != 5353 {
		t.Errorf("udp: %+v", s)
	}
}

// winRow4 builds a MIB_TCPROW_OWNER_PID.
func winRow4(state uint32, local net.IP, lport int, remote net.IP, rport int, pid uint32) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[0:], state)
	copy(b[4:8], local.To4())
	binary.LittleEndian.PutUint32(b[8:], uint32(lport>>8|(lport&0xff)<<8))
	copy(b[12:16], remote.To4())
	binary.LittleEndian.PutUint32(b[16:], uint32(rport>>8|(rport&0xff)<<8))
	binary.LittleEndian.PutUint32(b[20:], pid)
	return b
}

func TestParseWindowsTables(t *testing.T) {
	b := binary.LittleEndian.AppendUint32(nil, 2)
	b = append(b, winRow4(2, net.IPv4zero, 445, net.IPv4zero, 0, 4)...)
	b = append(b, winRow4(5, net.ParseIP("192.168.0.200"), 50123, net.ParseIP("160.79.104.10"), 443, 8032)...)
	ss := ParseTCPTable(b, false)
	if len(ss) != 2 || ss[0].State != "LISTEN" || ss[0].LocalPort != 445 || ss[0].PID != 4 || ss[0].RemoteIP != "" {
		t.Fatalf("listen: %+v", ss)
	}
	if s := ss[1]; s.State != "ESTABLISHED" || s.LocalPort != 50123 || s.RemoteIP != "160.79.104.10" || s.RemotePort != 443 || s.PID != 8032 {
		t.Errorf("conn: %+v", s)
	}
	// IPv6: ::1 port 42050, listening, PID 6332.
	r6 := make([]byte, 56)
	r6[15] = 1
	binary.LittleEndian.PutUint32(r6[20:], uint32(42050>>8|(42050&0xff)<<8))
	binary.LittleEndian.PutUint32(r6[48:], 2)
	binary.LittleEndian.PutUint32(r6[52:], 6332)
	ss = ParseTCPTable(append(binary.LittleEndian.AppendUint32(nil, 1), r6...), true)
	if len(ss) != 1 || ss[0].LocalIP != "::1" || ss[0].LocalPort != 42050 || ss[0].PID != 6332 || ss[0].Scope() != "local" {
		t.Errorf("tcp6: %+v", ss)
	}
	u := binary.LittleEndian.AppendUint32(nil, 1)
	u = append(u, 0, 0, 0, 0)
	u = binary.LittleEndian.AppendUint32(u, uint32(53<<8))
	u = binary.LittleEndian.AppendUint32(u, 5200)
	if ss := ParseUDPTable(u, false); len(ss) != 1 || ss[0].LocalPort != 53 || ss[0].PID != 5200 || ss[0].LocalIP != "0.0.0.0" {
		t.Errorf("udp: %+v", ss)
	}
	if ParseTCPTable([]byte{1}, false) != nil || len(ParseTCPTable(binary.LittleEndian.AppendUint32(nil, 9), false)) != 0 {
		t.Error("short buffers")
	}
}

func TestListenersAndConnections(t *testing.T) {
	ss := []Socket{
		{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 80, State: "LISTEN"},
		{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 80, State: "LISTEN"}, // duplicate
		{Proto: "tcp", LocalIP: "127.0.0.1", LocalPort: 22, State: "LISTEN"},
		{Proto: "udp", LocalIP: "0.0.0.0", LocalPort: 5353, State: "BOUND"},
		{Proto: "tcp", LocalIP: "10.0.0.2", LocalPort: 5000, RemoteIP: "1.1.1.1", RemotePort: 443, State: "ESTABLISHED", Process: "b"},
		{Proto: "tcp", LocalIP: "10.0.0.2", LocalPort: 5001, RemoteIP: "1.1.1.1", RemotePort: 443, State: "TIME_WAIT", Process: "a"},
		{Proto: "tcp", LocalIP: "10.0.0.2", LocalPort: 5002, RemoteIP: "8.8.8.8", RemotePort: 443, State: "CLOSE_WAIT", Process: "a"},
	}
	l := Listeners(ss)
	if len(l) != 3 || l[0].LocalPort != 22 || l[2].LocalPort != 5353 {
		t.Errorf("listeners: %+v", l)
	}
	if c := Connections(ss, false); len(c) != 2 || c[0].Process != "a" || c[0].State != "CLOSE_WAIT" {
		t.Errorf("connections: %+v", c)
	}
	if c := Connections(ss, true); len(c) != 3 {
		t.Errorf("--all: %+v", c)
	}
	if (Socket{LocalIP: "192.168.0.200"}).Scope() != "interface" {
		t.Error("one address is one interface")
	}
}
