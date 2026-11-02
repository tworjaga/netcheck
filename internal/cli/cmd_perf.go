package cli

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/perf"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// perfDefault: a bare --fail-on value is the slowest acceptable download,
// in Mbit/s ("--fail-on 100").
var perfDefault = adv.Default{Metric: "down", Op: '<'}

// parseRate reads "50M", "1G", "500k" or a plain number as bits per second.
func parseRate(s string) (int64, error) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(s), "bps"), "bit/s"))
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "g"):
		mult, s = 1e9, s[:len(s)-1]
	case strings.HasSuffix(s, "m"):
		mult, s = 1e6, s[:len(s)-1]
	case strings.HasSuffix(s, "k"):
		mult, s = 1e3, s[:len(s)-1]
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("%q isn't a rate (try 50M or 1G)", s)
	}
	return int64(v * mult), nil
}

// swing is how much the samples vary: their spread relative to the mean.
func swing(s []float64) float64 {
	if len(s) < 3 {
		return 0
	}
	// Leave out the first sample: TCP is still ramping up.
	s = s[1:]
	mean := 0.0
	for _, v := range s {
		mean += v
	}
	mean /= float64(len(s))
	if mean == 0 {
		return 0
	}
	var sq float64
	for _, v := range s {
		sq += (v - mean) * (v - mean)
	}
	return math.Sqrt(sq/float64(len(s))) / mean
}

var testNames = map[string]string{perf.TCPDown: "Download", perf.TCPUp: "Upload", perf.UDP: "UDP"}

func perfVerdict(host string, rs []perf.Result, udpRate int64) (ui.Status, string, []string) {
	var notes []string
	st := ui.OK
	var parts []string
	speed := map[string]float64{}
	for _, r := range rs {
		if r.Error != "" {
			return ui.Bad, fmt.Sprintf("The %s test failed: %s.", strings.ToLower(testNames[r.Test]), r.Error), nil
		}
		speed[r.Test] = r.Mbps
		switch r.Test {
		case perf.TCPDown, perf.TCPUp:
			parts = append(parts, strings.ToLower(testNames[r.Test])+" "+fmtMbps(r.Mbps))
			if sw := swing(r.Samples); sw > 0.35 {
				notes = append(notes, fmt.Sprintf("The %s speed swings a lot from moment to moment; Wi-Fi, a busy link or another transfer at the same time does that.", strings.ToLower(testNames[r.Test])))
			}
		case perf.UDP:
			u := r.UDP
			parts = append(parts, fmt.Sprintf("UDP at %s: %.1f%% lost, jitter %.1f ms", fmtMbps(float64(udpRate)/1e6), u.LossPct, u.JitterMs))
			if u.LossPct > 1 {
				st = ui.Warn
				notes = append(notes, fmt.Sprintf("%.1f%% of the packets got lost at %s: the link, or something on it, can't keep up at that rate. Lower --udp to find where the loss starts.", u.LossPct, fmtMbps(float64(udpRate)/1e6)))
			}
			if u.JitterMs > 30 {
				st = ui.Warn
				notes = append(notes, fmt.Sprintf("Jitter of %.0f ms makes calls and games stutter; Wi-Fi under load is the usual cause.", u.JitterMs))
			}
			if asked := float64(udpRate) / 1e6; r.Mbps < asked*0.8 && u.LossPct < 5 {
				notes = append(notes, fmt.Sprintf("Only %s arrived of the %s asked for, with little loss: this machine couldn't send faster, so the link's limit is higher than this test reached.", fmtMbps(r.Mbps), fmtMbps(asked)))
			}
			if u.OutOfOrder > 0 {
				notes = append(notes, fmt.Sprintf("%d packets arrived out of order: the traffic takes more than one path.", u.OutOfOrder))
			}
		}
	}
	if d, u := speed[perf.TCPDown], speed[perf.TCPUp]; d > 0 && u > 0 {
		if lo, hi := math.Min(d, u), math.Max(d, u); lo < hi*0.6 {
			slow := "Upload"
			if d < u {
				slow = "Download"
			}
			notes = append(notes, fmt.Sprintf("%s is much slower than the other direction (%s against %s): an asymmetric line, a duplex mismatch, or a congested link one way.", slow, fmtMbps(lo), fmtMbps(hi)))
		}
	}
	return st, upperFirst(strings.Join(parts, ", ")) + fmt.Sprintf(", between here and %s.", host), notes
}

func perfTable(rs []perf.Result, udpRate int64) ui.Table {
	tb := ui.Table{Headers: []string{"Test", "Speed", "Streams", "Over time"}}
	for _, r := range rs {
		st := ui.OK
		speed, streams := fmtMbps(r.Mbps), fmt.Sprint(r.Streams)
		if r.Error != "" {
			st, speed = ui.Bad, ui.Dim("failed")
		}
		if r.UDP != nil {
			streams = fmt.Sprintf("%.1f%% lost · %.1f ms jitter", r.UDP.LossPct, r.UDP.JitterMs)
			if r.UDP.LossPct > 1 || r.UDP.JitterMs > 30 {
				st = ui.Warn
			}
			speed += ui.Dim(" of " + fmtMbps(float64(udpRate)/1e6))
		}
		tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: []string{testNames[r.Test], speed, streams, ui.Trend(r.Samples)}})
	}
	return tb
}

func perfServer(ctx context.Context, port int, once, asJSON bool) int {
	ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(port)))
	if err != nil {
		ui.Verdict(ui.Bad, fmt.Sprintf("Couldn't listen on port %d: %v.", port, err))
		return 1
	}
	me := "this machine's address"
	if ip := probe.LocalIP(); ip != nil {
		me = ip.String()
	}
	ui.Println(fmt.Sprintf("  Listening on port %d. On the other machine, run:", port))
	cmd := "netcheck perf " + me
	if port != perf.DefaultPort {
		cmd += fmt.Sprintf(" -p %d", port)
	}
	ui.Println("    " + ui.Bold(cmd))
	ui.Println("  " + ui.Dim(fmt.Sprintf("If it can't connect, `netcheck port %d` shows what blocks it. Ctrl-C stops the server.", port)))
	ui.Println("")
	s := &perf.Server{Log: func(peer string, r perf.Result) {
		host, _, _ := net.SplitHostPort(peer)
		line := fmt.Sprintf("  %s  %-15s %-8s %s", time.Now().Format("15:04:05"), host, testNames[r.Test], fmtMbps(r.Mbps))
		if r.UDP != nil {
			line += fmt.Sprintf(" · %.1f%% lost · %.1f ms jitter", r.UDP.LossPct, r.UDP.JitterMs)
		}
		if asJSON {
			printJSON(map[string]any{"peer": host, "result": r})
			return
		}
		fmt.Println(line)
	}}
	if err := s.Serve(ctx, ln, once); err != nil {
		ui.Verdict(ui.Bad, "The server stopped: "+err.Error()+".")
		return 1
	}
	return 0
}

func cmdPerf(args []string) int {
	fs := flag.NewFlagSet("perf", flag.ExitOnError)
	common := adv.Register(fs)
	server := fs.Bool("server", false, "wait for a client on this machine")
	once := fs.Bool("once", false, "with --server: stop after one client")
	port := fs.Int("p", perf.DefaultPort, "port")
	dur := fs.Duration("t", 5*time.Second, "how long each direction runs")
	streams := fs.Int("P", 4, "parallel TCP streams")
	down := fs.Bool("down", false, "download only")
	up := fs.Bool("up", false, "upload only")
	udp := fs.String("udp", "", "UDP test at this rate instead, e.g. 50M: loss and jitter")
	size := fs.Int("size", 1200, "UDP packet size in bytes")
	pos := parseInterspersed(fs, args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck perf: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck perf --server [--once]   (on one machine)")
		fmt.Fprintln(os.Stderr, "       netcheck perf <host> [-t 5s] [-P 4] [--down|--up] [--udp 50M]   (on the other)")
		return 2
	}
	switch {
	case *port < 1 || *port > 65535:
		return usage("-p is a port")
	case *dur < time.Second || *dur > 60*time.Second:
		return usage("-t is 1s to 60s")
	case *streams < 1 || *streams > 16:
		return usage("-P is 1 to 16")
	case *size < 64 || *size > 65000:
		return usage("--size is 64 to 65000 bytes")
	}
	if *server {
		if len(pos) > 0 {
			return usage("--server takes no host")
		}
		ui.Title("perf server")
		return perfServer(ctx, *port, *once, common.JSON)
	}
	if len(pos) != 1 {
		return usage("name the machine running `netcheck perf --server`")
	}
	rules, err := common.Rules()
	if err != nil {
		return usage(err.Error())
	}
	ui.SetQuiet(common.JSON)
	addr := net.JoinHostPort(pos[0], strconv.Itoa(*port))
	var reqs []perf.Request
	var udpRate int64
	if *udp != "" {
		udpRate, err = parseRate(*udp)
		if err != nil {
			return usage(err.Error())
		}
		reqs = []perf.Request{{Test: perf.UDP, Streams: 1, Duration: *dur, Rate: udpRate, Size: *size}}
	} else {
		if !*up {
			reqs = append(reqs, perf.Request{Test: perf.TCPDown, Streams: *streams, Duration: *dur})
		}
		if !*down {
			reqs = append(reqs, perf.Request{Test: perf.TCPUp, Streams: *streams, Duration: *dur})
		}
	}
	reqs[len(reqs)-1].Last = true
	ui.Title("perf")
	var rs []perf.Result
	for _, q := range reqs {
		name := testNames[q.Test]
		var samples []float64
		ui.Live(fmt.Sprintf("  %s  %s", ui.Pad(name, 9), ui.Dim("starting…")))
		r := perf.Run(ctx, addr, q, func(v float64) {
			samples = append(samples, v)
			ui.Live(fmt.Sprintf("  %s  %-13s %s", ui.Pad(name, 9), fmtMbps(v), ui.Trend(tail(samples, 30))))
		})
		ui.LiveEnd("")
		if ctx.Err() != nil {
			return 130
		}
		rs = append(rs, r)
		if r.Error != "" {
			break
		}
	}
	st, msg, notes := perfVerdict(pos[0], rs, udpRate)
	vals := map[string]float64{}
	for _, r := range rs {
		switch {
		case r.Error != "":
		case r.Test == perf.TCPDown:
			vals["down"] = r.Mbps
		case r.Test == perf.TCPUp:
			vals["up"] = r.Mbps
		case r.UDP != nil:
			vals["loss"], vals["jitter"] = r.UDP.LossPct, r.UDP.JitterMs
		}
	}
	broken := adv.Broken(rules, perfDefault, vals)
	ui.Open(fmt.Sprintf("Here ⇄ %s · %s each", pos[0], *dur))
	for _, l := range perfTable(rs, udpRate).Lines(ui.PanelWidth()) {
		ui.Println(l)
	}
	ui.Close()
	if !common.Raw {
		ui.Verdict(st, msg, append(notes, broken...)...)
	}
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "perf", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: rs, FailedOn: broken}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), broken)
}
