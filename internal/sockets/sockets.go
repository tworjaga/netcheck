// Package sockets lists this machine's TCP and UDP sockets and the programs
// that own them: what's listening, and what's connected where.
package sockets

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Socket is one TCP or UDP socket.
type Socket struct {
	Proto      string `json:"proto"` // "tcp" or "udp"
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	State      string `json:"state"` // LISTEN, ESTABLISHED, ...; UDP: "BOUND"
	PID        int    `json:"pid,omitempty"`
	Process    string `json:"process,omitempty"`
}

// Listening reports a socket waiting for others to connect (or, for UDP,
// a bound socket with no fixed peer).
func (s Socket) Listening() bool {
	return s.State == "LISTEN" || s.Proto == "udp" && (s.RemoteIP == "" || s.RemotePort == 0)
}

// Scope says who can reach a listening socket: "local" (this machine only),
// "all" (every interface: the network too, unless a firewall stops it) or
// "interface" (one address).
func (s Socket) Scope() string {
	ip := net.ParseIP(s.LocalIP)
	switch {
	case ip == nil:
		return "all"
	case ip.IsLoopback():
		return "local"
	case ip.IsUnspecified():
		return "all"
	}
	return "interface"
}

// Snapshot is the list, and what limited it.
type Snapshot struct {
	Sockets []Socket `json:"sockets"`
	// Partial: some sockets' owners couldn't be seen (other users'
	// processes, without root on Linux or admin rights on macOS).
	Partial bool   `json:"partial,omitempty"`
	Method  string `json:"method"`
}

// List returns the machine's sockets.
func List() (Snapshot, error) { return list() }

// Listeners keeps the listening sockets, one per protocol, address and
// port, sorted by port.
func Listeners(ss []Socket) []Socket {
	var out []Socket
	seen := map[string]bool{}
	for _, s := range ss {
		key := fmt.Sprintf("%s %s %d", s.Proto, s.LocalIP, s.LocalPort)
		if !s.Listening() || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].LocalPort != out[j].LocalPort {
			return out[i].LocalPort < out[j].LocalPort
		}
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].LocalIP < out[j].LocalIP
	})
	return out
}

// Connections keeps TCP sockets with a peer (everything but LISTEN), sorted
// by program, then peer.
func Connections(ss []Socket, all bool) []Socket {
	var out []Socket
	for _, s := range ss {
		if s.Proto != "tcp" || s.State == "LISTEN" || s.RemoteIP == "" {
			continue
		}
		if !all && s.State != "ESTABLISHED" && s.State != "SYN_SENT" && s.State != "CLOSE_WAIT" {
			continue
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Process != out[j].Process {
			return strings.ToLower(out[i].Process) < strings.ToLower(out[j].Process)
		}
		if out[i].RemoteIP != out[j].RemoteIP {
			return out[i].RemoteIP < out[j].RemoteIP
		}
		return out[i].RemotePort < out[j].RemotePort
	})
	return out
}

// --- Linux /proc/net ---

var procStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
	"06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// procAddr reads "0100007F:0035": the address as 32-bit words in host
// (little-endian) order, then the port in hex.
func procAddr(s string) (string, int, error) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, fmt.Errorf("bad address %q", s)
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(ip[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q", s)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.String(), int(port), nil
}

// ParseProcNet reads one /proc/net/{tcp,tcp6,udp,udp6} file. inodes maps
// each socket's inode to its line, so owners can be filled in later.
func ParseProcNet(text, proto string) ([]Socket, []string, error) {
	var out []Socket
	var inodes []string
	sc := bufio.NewScanner(strings.NewReader(text))
	first := true
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if first {
			first = false
			continue
		}
		if len(f) < 10 {
			continue
		}
		lip, lport, err := procAddr(f[1])
		if err != nil {
			return nil, nil, err
		}
		rip, rport, err := procAddr(f[2])
		if err != nil {
			return nil, nil, err
		}
		s := Socket{Proto: proto, LocalIP: lip, LocalPort: lport, State: procStates[strings.ToUpper(f[3])]}
		if net.ParseIP(rip).IsUnspecified() {
			rip, rport = "", 0
		}
		s.RemoteIP, s.RemotePort = rip, rport
		if proto == "udp" {
			s.State = "BOUND"
			if rip != "" {
				s.State = "CONNECTED"
			}
		}
		out = append(out, s)
		inodes = append(inodes, f[9])
	}
	return out, inodes, nil
}

// --- macOS lsof -F ---

// ParseLsof reads `lsof -nP -iTCP -iUDP -F pcPnT`: p<pid>, c<command>, then
// per file P<proto>, n<local[->remote]>, T<TST=state> lines.
func ParseLsof(text string) []Socket {
	var out []Socket
	pid, cmd := 0, ""
	var cur *Socket
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	split := func(hp string) (string, int) {
		i := strings.LastIndex(hp, ":")
		if i < 0 {
			return hp, 0
		}
		port, _ := strconv.Atoi(hp[i+1:])
		host := strings.Trim(hp[:i], "[]")
		if host == "*" {
			host = "0.0.0.0"
			if strings.HasPrefix(hp, "[") {
				host = "::"
			}
		}
		return host, port
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			continue
		}
		v := l[1:]
		switch l[0] {
		case 'p':
			flush()
			pid, _ = strconv.Atoi(v)
		case 'c':
			cmd = v
		case 'f':
			flush()
		case 'P':
			flush()
			cur = &Socket{Proto: strings.ToLower(v), PID: pid, Process: cmd}
		case 'n':
			if cur == nil {
				continue
			}
			local, remote, _ := strings.Cut(v, "->")
			cur.LocalIP, cur.LocalPort = split(local)
			if remote != "" {
				cur.RemoteIP, cur.RemotePort = split(remote)
			}
			if cur.Proto == "udp" {
				cur.State = "BOUND"
				if remote != "" {
					cur.State = "CONNECTED"
				}
			}
		case 'T':
			if cur != nil && strings.HasPrefix(v, "ST=") {
				cur.State = strings.TrimPrefix(v, "ST=")
				if cur.State == "CLOSED" && cur.RemoteIP == "" {
					cur.State = "CLOSE"
				}
			}
		}
	}
	flush()
	return out
}

// --- Windows MIB tables ---

var winStates = map[uint32]string{
	1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED", 6: "FIN_WAIT1",
	7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}

// winPort: ports sit in network order in the low 16 bits of a DWORD.
func winPort(dw uint32) int { return int(dw&0xff)<<8 | int(dw>>8&0xff) }

// ParseTCPTable reads a MIB_TCPTABLE_OWNER_PID (v6 false) or
// MIB_TCP6TABLE_OWNER_PID (v6 true) as GetExtendedTcpTable fills it.
func ParseTCPTable(b []byte, v6 bool) []Socket {
	if len(b) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(b))
	var out []Socket
	if !v6 {
		const row = 24
		for i := 0; i < n && 4+(i+1)*row <= len(b); i++ {
			r := b[4+i*row:]
			u := func(k int) uint32 { return binary.LittleEndian.Uint32(r[k*4:]) }
			s := Socket{Proto: "tcp", LocalIP: net.IP(r[4:8]).String(), LocalPort: winPort(u(2)),
				RemoteIP: net.IP(r[12:16]).String(), RemotePort: winPort(u(4)), State: winStates[u(0)], PID: int(u(5))}
			if s.State == "LISTEN" {
				s.RemoteIP, s.RemotePort = "", 0
			}
			out = append(out, s)
		}
		return out
	}
	// ucLocalAddr[16] LocalScopeId LocalPort ucRemoteAddr[16] RemoteScopeId RemotePort State OwningPid
	const row = 56
	for i := 0; i < n && 4+(i+1)*row <= len(b); i++ {
		r := b[4+i*row:]
		s := Socket{Proto: "tcp", LocalIP: net.IP(append([]byte(nil), r[0:16]...)).String(), LocalPort: winPort(binary.LittleEndian.Uint32(r[20:])),
			RemoteIP: net.IP(append([]byte(nil), r[24:40]...)).String(), RemotePort: winPort(binary.LittleEndian.Uint32(r[44:])),
			State: winStates[binary.LittleEndian.Uint32(r[48:])], PID: int(binary.LittleEndian.Uint32(r[52:]))}
		if s.State == "LISTEN" {
			s.RemoteIP, s.RemotePort = "", 0
		}
		out = append(out, s)
	}
	return out
}

// ParseUDPTable reads a MIB_UDPTABLE_OWNER_PID or MIB_UDP6TABLE_OWNER_PID.
func ParseUDPTable(b []byte, v6 bool) []Socket {
	if len(b) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(b))
	var out []Socket
	row := 12
	if v6 {
		row = 28 // ucLocalAddr[16] LocalScopeId LocalPort OwningPid
	}
	for i := 0; i < n && 4+(i+1)*row <= len(b); i++ {
		r := b[4+i*row:]
		s := Socket{Proto: "udp", State: "BOUND"}
		if v6 {
			s.LocalIP = net.IP(append([]byte(nil), r[0:16]...)).String()
			s.LocalPort, s.PID = winPort(binary.LittleEndian.Uint32(r[20:])), int(binary.LittleEndian.Uint32(r[24:]))
		} else {
			s.LocalIP = net.IP(r[0:4]).String()
			s.LocalPort, s.PID = winPort(binary.LittleEndian.Uint32(r[4:])), int(binary.LittleEndian.Uint32(r[8:]))
		}
		out = append(out, s)
	}
	return out
}
