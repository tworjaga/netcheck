package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// openHit is one connection (or UDP datagram) that reached the port.
type openHit struct {
	Time  time.Time `json:"time"`
	Peer  string    `json:"peer"`
	Proto string    `json:"proto"`
	First string    `json:"first,omitempty"` // the first line it sent, if any
}

// greeting is what visitors get: plain text, or a small HTTP page when
// they spoke HTTP (a browser, `netcheck http`).
func greeting(host string, port int, first string) string {
	text := fmt.Sprintf("netcheck: you reached %s on port %d. Nothing else is here; it's a test.\n", host, port)
	if f := strings.Fields(first); len(f) == 3 && strings.HasPrefix(f[2], "HTTP/") {
		return "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: " +
			strconv.Itoa(len(text)) + "\r\n\r\n" + text
	}
	return text
}

// printable keeps the readable start of what a visitor sent.
func printable(s string) string {
	s = strings.TrimRight(s, "\r\n")
	var b strings.Builder
	for _, r := range s {
		if r < 32 || r == 127 {
			r = '.'
		}
		b.WriteRune(r)
	}
	return ui.Cut(b.String(), 60)
}

// serveOpen answers TCP visitors until ctx ends, reporting each.
func serveOpen(ctx context.Context, ln net.Listener, host string, port int, hit func(openHit)) {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			line, _ := bufio.NewReader(c).ReadString('\n')
			h := openHit{Time: time.Now(), Peer: c.RemoteAddr().String(), Proto: "tcp", First: printable(line)}
			c.Write([]byte(greeting(host, port, line)))
			hit(h)
		}()
	}
}

// serveOpenUDP answers each datagram.
func serveOpenUDP(ctx context.Context, pc net.PacketConn, host string, port int, hit func(openHit)) {
	go func() { <-ctx.Done(); pc.Close() }()
	buf := make([]byte, 65536)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pc.WriteTo([]byte(greeting(host, port, "")), from)
		hit(openHit{Time: time.Now(), Peer: from.String(), Proto: "udp", First: printable(string(buf[:n]))})
	}
}

func cmdOpen(args []string) int {
	fs := flag.NewFlagSet("open", flag.ExitOnError)
	common := adv.Register(fs)
	udp := fs.Bool("udp", false, "a UDP port")
	bind := fs.String("bind", "", "listen on this address only (default: every address)")
	dur := fs.Duration("t", 0, "stop after this long (default: Ctrl-C)")
	pos := parseInterspersed(fs, args)
	ui.SetQuiet(common.JSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck open: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck open <port> [--udp] [-t 10m] [--bind address]")
		return 2
	}
	if len(pos) != 1 {
		return usage("give the port to open")
	}
	port, err := strconv.Atoi(pos[0])
	if err != nil || port < 1 || port > 65535 {
		return usage(fmt.Sprintf("%q isn't a port", pos[0]))
	}
	if *dur > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *dur)
		defer cancel()
	}
	proto := "tcp"
	if *udp {
		proto = "udp"
	}
	addr := net.JoinHostPort(*bind, strconv.Itoa(port))
	var ln net.Listener
	var pc net.PacketConn
	if *udp {
		pc, err = net.ListenPacket("udp", addr)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	ui.Title("open")
	if err != nil {
		msg := fmt.Sprintf("Couldn't open %s %d: %v.", strings.ToUpper(proto), port, err)
		switch {
		case strings.Contains(err.Error(), "in use") || strings.Contains(err.Error(), "Only one usage"):
			msg = fmt.Sprintf("%s %d is already in use; `netcheck listen` shows by what.", strings.ToUpper(proto), port)
		case strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "access"):
			msg = fmt.Sprintf("Ports below 1024 need root here; try sudo, or a port above 1024.")
		}
		ui.Verdict(ui.Bad, msg)
		ui.Println("")
		return 1
	}
	me := "this machine"
	if ip := probe.LocalIP(); ip != nil {
		me = ip.String()
	}
	if *bind != "" {
		me = *bind
	}
	ui.Println(fmt.Sprintf("  %s %d is open. From another machine, try:", strings.ToUpper(proto), port))
	if *udp {
		ui.Println("    " + ui.Bold(fmt.Sprintf("netcheck connect %s:%d --udp", me, port)))
	} else {
		ui.Println("    " + ui.Bold(fmt.Sprintf("netcheck connect %s:%d", me, port)) + ui.Dim("   or http://"+net.JoinHostPort(me, strconv.Itoa(port))+" in a browser"))
	}
	ui.Println("  " + ui.Dim(fmt.Sprintf("From outside your network: `netcheck port %d` checks the way in. Ctrl-C stops.", port)))
	ui.Println("")

	var mu sync.Mutex
	var hits []openHit
	peers := map[string]bool{}
	hit := func(h openHit) {
		mu.Lock()
		hits = append(hits, h)
		host, _, _ := net.SplitHostPort(h.Peer)
		peers[host] = true
		mu.Unlock()
		if common.JSON {
			return
		}
		line := fmt.Sprintf("  %s  %s", h.Time.Format("15:04:05"), ui.Pad(h.Peer, 22))
		if h.First != "" {
			line += ui.Dim(h.First)
		}
		ui.Println(line)
	}
	if *udp {
		serveOpenUDP(ctx, pc, me, port, hit)
	} else {
		serveOpen(ctx, ln, me, port, hit)
	}
	mu.Lock()
	defer mu.Unlock()
	msg := fmt.Sprintf("Nobody connected to %s %d.", strings.ToUpper(proto), port)
	if len(hits) > 0 {
		msg = fmt.Sprintf("%s from %s reached %s %d.", plural(len(hits), map[bool]string{true: "datagram", false: "connection"}[*udp], map[bool]string{true: "datagrams", false: "connections"}[*udp]), plural(len(peers), "address", "addresses"), strings.ToUpper(proto), port)
	}
	ui.Println("")
	ui.Verdict(ui.OK, msg)
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "open", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: "ok", Message: msg}, Data: map[string]any{"port": port, "proto": proto, "hits": hits}}.Write(os.Stdout)
	}
	return 0
}
