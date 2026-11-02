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
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/sockets"
	"github.com/tworjaga/netcheck/internal/tracex"
	"github.com/tworjaga/netcheck/internal/ui"
)

// conn is one connection with what's known about the other end.
type conn struct {
	sockets.Socket
	Count int    `json:"count"` // identical connections folded into this one
	Host  string `json:"remote_name,omitempty"`
	ASN   int    `json:"remote_asn,omitempty"`
	Owner string `json:"remote_owner,omitempty"`
}

// Test seams for naming the other ends.
var (
	connAddr  = net.DefaultResolver.LookupAddr
	connOwner = tracex.LookupOwner
)

// nameRemotes looks up each distinct remote address once, all at once.
func nameRemotes(ctx context.Context, cs []conn) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	type info struct {
		host, owner string
		asn         int
	}
	found := map[string]*info{}
	for _, c := range cs {
		found[c.RemoteIP] = &info{}
	}
	var wg sync.WaitGroup
	for ip, in := range found {
		addr := net.ParseIP(ip)
		if addr == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if names, err := connAddr(ctx, ip); err == nil && len(names) > 0 {
				in.host = strings.TrimSuffix(names[0], ".")
			}
			switch {
			case addr.IsLoopback():
				in.owner = "this machine"
			case addr.IsPrivate(), addr.IsLinkLocalUnicast():
				in.owner = "local network"
			default:
				o := connOwner(ctx, addr)
				in.asn, in.owner = o.ASN, tracex.ShortOwner(o.Name)
			}
		}()
	}
	wg.Wait()
	for i := range cs {
		in := found[cs[i].RemoteIP]
		cs[i].Host, cs[i].ASN, cs[i].Owner = in.host, in.asn, in.owner
	}
}

func remoteText(c conn) string {
	host := c.Host
	if host == "" {
		host = c.RemoteIP
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, c.RemotePort)
}

// connFindings looks for programs in trouble: connections piling up
// unclosed, or attempts nobody answers.
func connFindings(cs []conn) (ui.Status, []string) {
	st := ui.OK
	var notes []string
	closeWait := map[string]int{}
	synSent := map[string][]string{}
	for _, c := range cs {
		switch c.State {
		case "CLOSE_WAIT":
			closeWait[c.Process]++
		case "SYN_SENT":
			synSent[c.Process] = append(synSent[c.Process], remoteText(c))
		}
	}
	for p, n := range closeWait {
		if n >= 10 {
			st = ui.Warn
			notes = append(notes, fmt.Sprintf("%s holds %d connections the other side has closed (CLOSE_WAIT): the program isn't closing its sockets, and they pile up until it's restarted.", firstNonEmpty(p, "A program"), n))
		}
	}
	for p, targets := range synSent {
		sort.Strings(targets)
		more := ""
		if len(targets) > 3 {
			targets, more = targets[:3], fmt.Sprintf(" and %d more", len(targets)-3)
		}
		notes = append(notes, fmt.Sprintf("%s is trying to reach %s%s and hasn't had an answer yet.", firstNonEmpty(p, "A program"), strings.Join(targets, ", "), more))
	}
	sort.Strings(notes)
	return st, notes
}

func connsVerdict(cs []conn, partial bool) (ui.Status, string, []string) {
	if len(cs) == 0 {
		return ui.OK, "No open connections.", nil
	}
	perProg := map[string]int{}
	owners := map[string]bool{}
	for _, c := range cs {
		perProg[c.Process]++
		if c.Owner != "" && c.Owner != "this machine" {
			owners[c.Owner] = true
		}
	}
	top, n := "", 0
	for p, k := range perProg {
		if k > n || k == n && p < top {
			top, n = p, k
		}
	}
	msg := fmt.Sprintf("%s from %s", plural(len(cs), "connection", "connections"), plural(len(perProg), "program", "programs"))
	if len(owners) > 0 {
		msg += fmt.Sprintf(" to %s", plural(len(owners), "network", "networks"))
	}
	msg += fmt.Sprintf("; the most from %s (%d).", firstNonEmpty(strings.TrimSuffix(top, ".exe"), "an unknown program"), n)
	st, notes := connFindings(cs)
	if partial {
		notes = append(notes, "Some connections belong to other users' programs and show without a name; run it with sudo to see them all.")
	}
	return st, msg, notes
}

// fold merges identical connections (same program name, peer and state) into
// one row with a count.
func fold(cs []conn) []conn {
	var out []conn
	idx := map[string]int{}
	for _, c := range cs {
		key := fmt.Sprintf("%s %s %d %s", c.Process, c.RemoteIP, c.RemotePort, c.State)
		if i, ok := idx[key]; ok {
			out[i].Count++
			continue
		}
		c.Count = 1
		idx[key] = len(out)
		out = append(out, c)
	}
	return out
}

func connsTable(cs []conn, width int) ui.Table {
	wide := width >= 110
	tb := ui.Table{Headers: []string{"Program", "Remote", "Owner", "State"}}
	for _, c := range cs {
		st := ui.OK
		switch c.State {
		case "CLOSE_WAIT":
			st = ui.Warn
		case "SYN_SENT":
			st = ui.Skip
		}
		owner := c.Owner
		if c.ASN != 0 && wide {
			owner = fmt.Sprintf("AS%d %s", c.ASN, c.Owner)
		}
		state := strings.ToLower(strings.ReplaceAll(c.State, "_", " "))
		if c.State == "ESTABLISHED" {
			state = "open"
		}
		pw, rw, ow := 14, 26, 16
		if wide {
			pw, rw, ow = 22, 46, 32
		}
		if c.Count > 1 {
			state += fmt.Sprintf(" ×%d", c.Count)
		}
		tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: []string{ui.Cut(firstNonEmpty(strings.TrimSuffix(c.Process, ".exe"), "?"), pw), ui.Cut(remoteText(c), rw), ui.Cut(owner, ow), state}})
	}
	return tb
}

func cmdConns(args []string) int {
	fs := flag.NewFlagSet("conns", flag.ExitOnError)
	common := adv.Register(fs)
	all := fs.Bool("all", false, "include closing connections (TIME_WAIT and the like)")
	prog := fs.String("p", "", "only this program (part of its name)")
	noNames := fs.Bool("n", false, "skip names and network owners")
	local := fs.Bool("local", false, "include connections between programs on this machine")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if len(pos) > 0 {
		fmt.Fprintln(os.Stderr, "netcheck conns: takes no arguments")
		fmt.Fprintln(os.Stderr, "usage: netcheck conns [-p program] [--all] [--local] [-n]")
		return 2
	}
	rules, err := common.Rules()
	if err != nil {
		fmt.Fprintln(os.Stderr, "netcheck conns: "+err.Error())
		return 2
	}
	hidden := 0
	look := func(ctx context.Context) ([]conn, sockets.Snapshot, error) {
		snap, err := listSockets()
		if err != nil {
			return nil, snap, err
		}
		var cs []conn
		hidden = 0
		for _, s := range sockets.Connections(snap.Sockets, *all) {
			if *prog != "" && !strings.Contains(strings.ToLower(s.Process), strings.ToLower(*prog)) {
				continue
			}
			if ip := net.ParseIP(s.RemoteIP); ip != nil && ip.IsLoopback() && !*local {
				hidden++
				continue
			}
			cs = append(cs, conn{Socket: s})
		}
		if !*noNames {
			nameRemotes(ctx, cs)
		}
		return cs, snap, nil
	}
	ui.Title("conns")
	if common.Watch > 0 {
		adv.Watch(ctx, common.Watch, func(ctx context.Context) []string {
			cs, snap, err := look(ctx)
			if err != nil {
				return []string{"  " + ui.Bad.Paint(err.Error())}
			}
			st, msg, _ := connsVerdict(cs, snap.Partial)
			return append(connsTable(fold(cs), ui.PanelWidth()).Lines(ui.PanelWidth()), "", "  "+st.Paint(msg))
		})
		return 0
	}
	t := ui.Begin("Looking")
	t.Progress("at this machine's connections…")
	cs, snap, err := look(ctx)
	t.Clear()
	if err != nil {
		ui.Verdict(ui.Bad, "Couldn't list the connections: "+err.Error()+".")
		ui.Println("")
		return 1
	}
	st, msg, notes := connsVerdict(cs, snap.Partial)
	if hidden > 0 {
		notes = append(notes, fmt.Sprintf("Not shown: %s between programs on this machine (--local shows them).", plural(hidden, "connection", "connections")))
	}
	closeWait := 0
	for _, c := range cs {
		if c.State == "CLOSE_WAIT" {
			closeWait++
		}
	}
	broken := adv.Broken(rules, adv.Default{Metric: "conns", Op: '>'}, map[string]float64{"conns": float64(len(cs)), "closewait": float64(closeWait)})
	if len(cs) > 0 {
		ui.Open(fmt.Sprintf("Connections · %d", len(cs)))
		for _, l := range connsTable(fold(cs), ui.PanelWidth()).Lines(ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
	}
	if !common.Raw {
		ui.Verdict(st, msg, append(notes, broken...)...)
	}
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "conns", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg},
			Data: map[string]any{"connections": cs, "partial": snap.Partial, "method": snap.Method}, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
