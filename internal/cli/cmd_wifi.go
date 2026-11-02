package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// wifiVerdict turns a Wi-Fi reading into a status, a plain-English sentence
// and a short note for table rows. Skip means "not on Wi-Fi / unknown".
func wifiVerdict(w probe.WifiInfo) (ui.Status, string, string) {
	switch {
	case w.Error != "":
		return ui.Skip, w.Error + ".", "unsupported"
	case !w.Available:
		return ui.Skip, "No Wi-Fi adapter found, so you're probably on a cable.", "no adapter"
	case !w.Connected:
		return ui.Skip, "This computer isn't connected to Wi-Fi right now.", "not connected"
	}
	q := probe.SignalQuality(w.SignalDBm)
	switch {
	case w.SignalDBm != 0 && w.SignalDBm < -75:
		return ui.Warn, fmt.Sprintf("Your Wi-Fi signal is %s (%d dBm). Move closer to the router or add an access point; weak signal causes slow speeds and drops.", q, w.SignalDBm), q + " signal"
	case w.Crowding == "crowded":
		msg := fmt.Sprintf("Wi-Fi channel %d is crowded: %d nearby networks overlap it.", w.Channel, w.Sharing)
		if w.BestChan != 0 {
			msg += fmt.Sprintf(" Switching your router to channel %d should help.", w.BestChan)
		} else {
			msg += " A different channel, or the 5 GHz band, should help."
		}
		return ui.Warn, msg, "crowded channel"
	}
	return ui.OK, fmt.Sprintf("Wi-Fi looks healthy: %s signal on %s.", q, bandLabel(w)), ""
}

func bandLabel(w probe.WifiInfo) string {
	if w.Band != "" {
		return w.Band
	}
	return "an unknown band"
}

func wifiRows(w probe.WifiInfo) {
	st, _, note := wifiVerdict(w)
	if !w.Connected {
		ui.Println(ui.Row("Wi-Fi", st, "–", "–", ui.Dim(note)))
		return
	}
	ssid := w.SSID
	if ssid == "" {
		ssid = "(hidden name)"
	}
	ui.Println(ui.Row("Network", ui.OK, ssid, "", ui.Dim(joinDot(w.Band, chanLabel(w.Channel), w.Radio))))
	sigSt := ui.OK
	if w.SignalDBm < -75 && w.SignalDBm != 0 {
		sigSt = ui.Warn
	}
	sigExtra := ui.Dim(fmt.Sprintf("%d%%", w.SignalPct))
	if ui.Framed() && w.SignalDBm != 0 {
		sigExtra = signalMeter(w.SignalDBm) + "  " + sigExtra
	}
	ui.Println(ui.Row("Signal", sigSt, probe.SignalQuality(w.SignalDBm), fmt.Sprintf("%d dBm", w.SignalDBm), sigExtra))
	if w.RateMbps > 0 {
		ui.Println(ui.Row("Link rate", ui.OK, fmt.Sprintf("%.0f Mbps", w.RateMbps), "", ""))
	}
	switch w.Crowding {
	case "":
		ui.Println(ui.Row("Channel", ui.Skip, "unknown", "–", ui.Dim("couldn't scan neighbours")))
	default:
		cs := ui.OK
		if w.Crowding == "crowded" {
			cs = ui.Warn
		}
		ui.Println(ui.Row("Channel", cs, w.Crowding, "", ui.Dim(fmt.Sprintf("%d nearby on ch %d", w.Sharing, w.Channel))))
	}
}

func chanLabel(c int) string {
	if c == 0 {
		return ""
	}
	return fmt.Sprintf("ch %d", c)
}

func joinDot(parts ...string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += " · "
		}
		out += p
	}
	return out
}

type wifiReport struct {
	probe.WifiInfo
	SignalHistory []int `json:"signal_history_dbm,omitempty"`
}

func cmdWifi(args []string) int {
	fs := flag.NewFlagSet("wifi", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	n := fs.Int("n", -1, "signal samples to watch, 1/s (0 = until Ctrl-C; default 15 on a terminal, none otherwise)")
	walk := fs.Bool("walk", false, "walk test: measure the signal spot by spot, then compare")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *walk {
		return cmdWifiWalk(ctx, *asJSON)
	}
	if *n < 0 && !*asJSON && ui.Interactive() {
		*n = 15 // a short live view by default, but never for pipes or JSON
	}

	ui.Title("wifi")
	ui.Open("Wi-Fi")
	defer ui.Close()
	t := ui.Begin("Wi-Fi")
	t.Progress("reading adapter…")
	w := probe.ReadWifi(ctx)
	t.Clear()
	rep := wifiReport{WifiInfo: w}
	wifiRows(w)
	st, msg, _ := wifiVerdict(w)
	ui.Verdict(st, msg, w.Note)
	ui.Println("")

	if w.Connected && *n >= 0 && ctx.Err() == nil {
		ui.Open("Signal over time")
		rep.SignalHistory = signalView(ctx, *n)
		ui.Close()
		if ctx.Err() != nil {
			ui.Println("")
		}
	}
	if *asJSON {
		printJSON(rep)
	}
	return 0
}

// signalView draws a scrolling signal-over-time strip: taller bars mean a
// stronger signal, on a fixed -90 to -40 dBm scale.
func signalView(ctx context.Context, samples int) []int {
	var vals []float64
	switch {
	case !ui.Framed():
		ui.Println("  " + ui.Dim("signal over time"+map[bool]string{true: "  (Ctrl-C to stop)", false: ""}[samples == 0]))
	case samples == 0: // the panel's title already says what this is
		ui.Println("  " + ui.Dim("Ctrl-C to stop"))
	}
	var blk ui.Block
	hist := probe.SampleSignal(ctx, time.Second, samples, probe.ReadWifi, func(dbm int) {
		v := float64(dbm)
		if dbm == 0 {
			v = -200
		}
		vals = append(vals, v)
		if ui.Framed() {
			now := ui.Alert("not connected")
			if dbm != 0 {
				now = fmt.Sprintf("%d dBm  %s", dbm, ui.Dim(probe.SignalQuality(dbm)))
			}
			blk.Update(append(ui.SignalChart(vals, 4, ui.PanelWidth()), "", "  "+ui.Dim("now")+" "+now))
			return
		}
		ui.Live("  " + ui.SignalBars(tail(vals, 48)) + "  " + ui.Dim(fmt.Sprintf("%d dBm", dbm)))
	})
	if ui.Framed() {
		blk.End(ui.SignalChart(vals, 4, ui.PanelWidth()))
		return hist
	}
	ui.LiveEnd("  " + ui.SignalBars(tail(vals, 48)))
	return hist
}

// signalMeter is the Signal row's gauge: -90 dBm empty, -40 dBm full,
// coloured by quality.
func signalMeter(dbm int) string {
	st := ui.OK
	switch {
	case dbm < -75:
		st = ui.Bad
	case dbm < -67:
		st = ui.Warn
	}
	return ui.Meter((float64(dbm)+90)/50, 10, st)
}
