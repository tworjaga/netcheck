package cli

import (
	"context"
	"flag"
	"fmt"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
	"os"
	"os/signal"
	"time"
)

func cmdPing(args []string) int {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	count := fs.Int("c", 20, "number of probes (0 = until Ctrl-C)")
	port := fs.Int("p", 443, "TCP port to probe (implies --tcp)")
	forceTCP := fs.Bool("tcp", false, "use TCP connects instead of ICMP")
	interval := fs.Duration("i", 250*time.Millisecond, "time between probes")
	asJSON := fs.Bool("json", false, "machine-readable output")
	pos := parseInterspersed(fs, args)
	host := "1.1.1.1"
	if len(pos) > 0 {
		host = pos[0]
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "p" {
			*forceTCP = true
		}
	})
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	method := fmt.Sprintf("tcp:%d", *port)
	if !*forceTCP && probe.ICMPAvailable() {
		method = "icmp"
	}
	ui.Title("ping")
	// On a terminal the replies draw a live chart inside a panel; piped
	// output keeps the one-line sparkline.
	charted := ui.Framed()
	if charted {
		ui.Open(host + " · " + method)
		defer ui.Close()
	} else {
		ui.Println("  " + host + ui.Dim("  "+method) + "\n")
	}

	live := ui.Interactive() && !*asJSON
	var samples []float64
	var blk ui.Block
	onSample := func(ms float64) {
		samples = append(samples, ms)
		if !live {
			return
		}
		last := ui.Alert("lost")
		if ms >= 0 {
			last = fmtMs(ms)
		}
		if charted {
			blk.Update(append(pingChart(samples), "", "  "+kv("last", last)+"   "+kv("sent", fmt.Sprint(len(samples)))))
			return
		}
		ui.Live("  " + ui.Spark(tail(samples, 48)) + "  " + last)
	}
	var res probe.PingResult
	if *forceTCP {
		res = probe.Ping(ctx, host, *port, *count, *interval, onSample)
	} else {
		res = probe.PingBest(ctx, host, []int{*port, 443, 80, 53}, *count, *interval, onSample)
	}
	if *asJSON {
		printJSON(res)
		if res.Error != "" || res.Received == 0 {
			return 1
		}
		return 0
	}
	if res.Error != "" {
		if charted {
			blk.End(nil)
		}
		ui.LiveEnd("  " + ui.Alert(res.Error))
		return 1
	}
	if res.Sent == 0 {
		return 0
	}

	loss := fmt.Sprintf("%.0f%%", res.LossPct)
	if res.LossPct > 2 {
		loss = ui.Caution(loss)
	}
	counts := "  " + kv("sent", fmt.Sprint(res.Sent)) + "   " + kv("received", fmt.Sprint(res.Received)) + "   " + kv("loss", loss)
	stats := "  " + kv("min", fmt.Sprintf("%.1f", res.MinMs)) + "   " + kv("avg", fmt.Sprintf("%.1f", res.AvgMs)) +
		"   " + kv("max", fmt.Sprintf("%.1f", res.MaxMs)) + "   " + kv("jitter", fmt.Sprintf("%.1f", res.JitterMs)) + ui.Dim(" ms")
	if charted {
		final := append(pingChart(res.SamplesMs), "")
		if res.Note != "" {
			final = append(final, "  "+ui.Dim(res.Note))
		}
		final = append(final, counts)
		if res.Received > 0 {
			final = append(final, stats)
		}
		blk.End(final)
		ui.Close()
		if res.Received == 0 {
			ui.Verdict(ui.Bad, "No replies. The host may be down, or blocking this port.")
			ui.Println("")
			return 1
		}
		ui.Println("")
		return 0
	}

	ui.LiveEnd("  " + ui.Spark(tail(res.SamplesMs, 48)))
	fmt.Println()
	if res.Note != "" {
		fmt.Println("  " + ui.Dim(res.Note) + "\n")
	}
	fmt.Println(counts)
	if res.Received > 0 {
		fmt.Println(stats)
	} else {
		fmt.Println("\n  " + ui.Alert("No replies.") + ui.Dim(" The host may be down, or blocking this port."))
		return 1
	}
	return 0
}

// pingChart is ping's live chart, as wide as the panel allows.
func pingChart(ms []float64) []string {
	return ui.LatencyChart(ms, 5, ui.PanelWidth())
}
