package cli

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// routeVerdict explains a traced path in plain English. Loss at a middle hop
// only matters if it carries through to the destination; many routers just
// answer pings slowly while forwarding traffic fine.
func routeVerdict(r probe.RouteResult) (ui.Status, string) {
	if r.Error != "" {
		return ui.Skip, "Couldn't trace the route: " + r.Error + "."
	}
	hops := r.Hops
	if len(hops) == 0 {
		return ui.Skip, "No router along the way answered, so the path is unknown."
	}
	last := hops[len(hops)-1]
	if r.Reached && last.Sent >= 5 && last.LossPct > 2 {
		origin := last
		for i := len(hops) - 1; i >= 0; i-- {
			if hops[i].IP != "" && hops[i].LossPct > 2 {
				origin = hops[i]
			} else if hops[i].IP != "" {
				break
			}
		}
		return ui.Warn, fmt.Sprintf("Packets are being lost on the way to %s (%.0f%% at the end). The loss starts at hop %d (%s)%s.", r.Target, last.LossPct, origin.TTL, origin.IP, whereIs(origin.TTL, origin.IP))
	}
	jump, at := 0.0, -1
	prev := 0.0
	for i, h := range hops {
		if h.Received == 0 {
			continue
		}
		if d := h.AvgMs - prev; d > jump {
			jump, at = d, i
		}
		prev = h.AvgMs
	}
	if at >= 0 && jump > 60 {
		h := hops[at]
		return ui.Warn, fmt.Sprintf("Latency jumps by %.0f ms at hop %d (%s)%s. Everything beyond it inherits that delay.", jump, h.TTL, h.IP, whereIs(h.TTL, h.IP))
	}
	if !r.Reached {
		return ui.Skip, fmt.Sprintf("The route fades out after hop %d. %s probably doesn't answer ping, which is normal.", last.TTL, r.Target)
	}
	return ui.OK, fmt.Sprintf("The path to %s looks clean: %d hops, %s end to end.", r.Target, len(hops), fmtMs(last.AvgMs))
}

// whereIs adds a plain-English location hint for a hop.
func whereIs(ttl int, addr string) string {
	ip := net.ParseIP(addr)
	switch {
	case ip == nil:
		return ""
	case ttl == 1 && ip.IsPrivate():
		return ", which is your router"
	case ip.IsPrivate():
		return ", still inside a private network"
	case ip.To4() != nil && ip.To4()[0] == 100 && ip.To4()[1]&0xC0 == 64:
		return ", your ISP's shared (carrier-grade NAT) network"
	}
	return ""
}

func routeLines(r probe.RouteResult, gw string) []string {
	if len(r.Hops) == 0 {
		return nil
	}
	lines := []string{"  " + ui.Dim(fmt.Sprintf("%-4s%-17s%6s  %9s", "hop", "address", "loss", "avg"))}
	for _, h := range r.Hops {
		num := fmt.Sprintf("%-4d", h.TTL)
		if h.IP == "" {
			lines = append(lines, "  "+num+ui.Dim(ui.Pad("no reply", 17)+fmt.Sprintf("%6s", "–")))
			continue
		}
		loss := fmt.Sprintf("%5.0f%%", h.LossPct)
		if h.LossPct > 2 && h.Sent >= 5 {
			loss = ui.Caution(loss)
		}
		avg := "–"
		if h.Received > 0 {
			avg = fmtMs(h.AvgMs)
		}
		note := ""
		switch {
		case h.IP == gw:
			note = "  " + ui.Dim("your router")
		case h.IP == r.Addr:
			note = "  " + ui.Dim("destination")
		}
		lines = append(lines, "  "+num+ui.Pad(h.IP, 17)+loss+fmt.Sprintf("  %9s  ", avg)+ui.Spark(tail(h.SamplesMs, 20))+note)
	}
	return lines
}

type routeReport struct {
	probe.RouteResult
	Verdict verdict `json:"verdict"`
}

func cmdRoute(args []string) int {
	fs := flag.NewFlagSet("route", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	rounds := fs.Int("c", 10, "probes per hop (0 = until Ctrl-C)")
	maxHops := fs.Int("m", 30, "maximum hops")
	interval := fs.Duration("i", 400*time.Millisecond, "time between rounds")
	pos := parseInterspersed(fs, args)
	host := "1.1.1.1"
	if len(pos) > 0 {
		host = pos[0]
	}
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	gwIP, _ := probe.DefaultGateway()
	gw := ""
	if gwIP != nil {
		gw = gwIP.String()
	}
	ui.Title("route")
	if ui.Framed() {
		ui.Open("Route to " + host)
		defer ui.Close()
	} else {
		ui.Println("  " + host + "\n")
	}

	var blk ui.Block
	t := ui.Begin("Tracing")
	started := false
	res := probe.Trace(ctx, host, probe.RouteOpts{MaxHops: *maxHops, Rounds: *rounds, Interval: *interval, OnUpdate: func(r probe.RouteResult) {
		if !started {
			started = true
			t.Clear()
		}
		blk.Update(routeLines(r, gw))
	}})
	if !started {
		t.Clear()
	}
	blk.End(routeLines(res, gw))
	interrupted := ctx.Err() != nil
	st, msg := routeVerdict(res)
	if interrupted && *rounds != 0 {
		st, msg = ui.Skip, "Interrupted."
	}
	ui.Verdict(st, msg, res.Note)
	ui.Println("")
	if *asJSON {
		printJSON(routeReport{res, verdict{st.String(), msg}})
	}
	switch {
	case res.Error != "" && !interrupted:
		return 1
	case interrupted && *rounds != 0:
		return 130
	}
	return 0
}
