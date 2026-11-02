package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

// walkSpot is the Wi-Fi signal measured at one place during a walk test.
type walkSpot struct {
	Name    string `json:"name"`
	DBm     int    `json:"signal_dbm"` // median; 0 = not connected there
	Quality string `json:"quality"`
	BSSID   string `json:"bssid,omitempty"`
	Band    string `json:"band,omitempty"`
	Channel int    `json:"channel,omitempty"`
	Samples []int  `json:"samples_dbm"`
}

// walkSamples are taken at each spot, one a second; the median counts, as
// a single reading jumps around by several dB.
const walkSamples = 5

// medianDBm is the median of the readings taken while connected.
func medianDBm(samples []int) int {
	var v []int
	for _, s := range samples {
		if s != 0 {
			v = append(v, s)
		}
	}
	if len(v) == 0 {
		return 0
	}
	sort.Ints(v)
	return v[len(v)/2]
}

// readLines feeds the lines of r into a channel, so waiting for the next
// spot's name can be cut short by Ctrl-C.
func readLines(r io.Reader) <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			ch <- sc.Text()
		}
	}()
	return ch
}

// walkSpots asks for a spot name, measures the signal there, and repeats
// until an empty line, the end of input, or Ctrl-C. A spot interrupted
// halfway is dropped.
func walkSpots(ctx context.Context, lines <-chan string, prompt func(), read func(context.Context) probe.WifiInfo, interval time.Duration, onSample func(name string, dbms []int)) []walkSpot {
	var spots []walkSpot
	for {
		prompt()
		var name string
		select {
		case <-ctx.Done():
			return spots
		case l, ok := <-lines:
			if !ok {
				return spots
			}
			name = strings.TrimSpace(l)
		}
		if name == "" {
			return spots
		}
		spot := walkSpot{Name: name}
		var got []int
		spot.Samples = probe.SampleSignal(ctx, interval, walkSamples, func(c context.Context) probe.WifiInfo {
			w := read(c)
			if w.Connected {
				spot.BSSID, spot.Band, spot.Channel = w.BSSID, w.Band, w.Channel
			}
			return w
		}, func(dbm int) {
			got = append(got, dbm)
			if onSample != nil {
				onSample(name, got)
			}
		})
		if len(spot.Samples) < walkSamples {
			return spots // Ctrl-C mid-spot
		}
		spot.DBm = medianDBm(spot.Samples)
		spot.Quality = "no Wi-Fi"
		if spot.DBm != 0 {
			spot.Quality = probe.SignalQuality(spot.DBm)
		}
		spots = append(spots, spot)
	}
}

// walkVerdict sums up a walk: the weak spots if any, else the weakest one.
func walkVerdict(spots []walkSpot) (ui.Status, string) {
	if len(spots) == 0 {
		return ui.Skip, "No spots were measured."
	}
	var none, weak []string
	worst := spots[0]
	for _, s := range spots {
		switch {
		case s.DBm == 0:
			none = append(none, s.Name)
		case s.DBm < -75:
			weak = append(weak, fmt.Sprintf("%s (%d dBm)", s.Name, s.DBm))
		}
		if s.DBm != 0 && (worst.DBm == 0 || s.DBm < worst.DBm) {
			worst = s
		}
	}
	switch {
	case len(none) > 0:
		return ui.Warn, "No Wi-Fi in " + joinAnd(none) + ". An extender or mesh point between there and the router would bring it in range."
	case len(weak) > 0:
		return ui.Warn, "The signal is weak in " + joinAnd(weak) + ", which means slow speeds and drops there. Moving the router or extender toward it, or adding a mesh point in between, would help."
	case worst.DBm < -67:
		return ui.OK, fmt.Sprintf("Usable everywhere you checked; weakest in %s (%d dBm, fair).", worst.Name, worst.DBm)
	}
	return ui.OK, fmt.Sprintf("Good signal everywhere you checked; weakest in %s (%d dBm).", worst.Name, worst.DBm)
}

// apLabels names access points "AP 1", "AP 2"… in the order the walk met
// them, but only when there was more than one: a mesh or an extender.
func apLabels(spots []walkSpot) map[string]string {
	labels := map[string]string{}
	var order []string
	for _, s := range spots {
		if s.BSSID != "" && labels[s.BSSID] == "" {
			order = append(order, s.BSSID)
			labels[s.BSSID] = fmt.Sprintf("AP %d", len(order))
		}
	}
	if len(order) < 2 {
		return map[string]string{}
	}
	return labels
}

// walkRows is the result table, strongest spot first.
func walkRows(spots []walkSpot) []string {
	sorted := append([]walkSpot(nil), spots...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i].DBm, sorted[j].DBm
		if a == 0 || b == 0 {
			return b == 0 && a != 0
		}
		return a > b
	})
	aps := apLabels(spots)
	var rows []string
	for _, s := range sorted {
		name := s.Name
		if len([]rune(name)) > 11 {
			name = string([]rune(name)[:10]) + "…"
		}
		if s.DBm == 0 {
			rows = append(rows, ui.Row(name, ui.Bad, "no Wi-Fi", "–", ""))
			continue
		}
		st := ui.OK
		if s.DBm < -75 {
			st = ui.Warn
		}
		rows = append(rows, ui.Row(name, st, s.Quality, fmt.Sprintf("%d dBm", s.DBm), ui.Dim(joinDot(s.Band, chanLabel(s.Channel), aps[s.BSSID]))))
	}
	return rows
}

// cmdWifiWalk runs the walk test: the signal room by room.
func cmdWifiWalk(ctx context.Context, asJSON bool) int {
	ui.Title("wifi walk")
	w := probe.ReadWifi(ctx)
	if !w.Connected {
		st, msg, _ := wifiVerdict(w)
		ui.Println("  " + st.Paint(msg))
		if w.Note != "" {
			ui.Println("  " + ui.Dim(w.Note))
		}
		ui.Println("")
		if asJSON {
			printJSON(struct {
				Spots   []walkSpot `json:"spots"`
				Verdict verdict    `json:"verdict"`
			}{[]walkSpot{}, verdict{st.String(), msg}})
		}
		return 0
	}
	// Prompts go to stderr with --json, so stdout stays machine-readable.
	var promptOut io.Writer = os.Stdout
	if asJSON {
		promptOut = os.Stderr
	}
	fmt.Fprintln(promptOut, "  "+ui.Dim("Go to a spot, type its name and press Enter. An empty line finishes."))
	prompt := func() { fmt.Fprint(promptOut, "\n  "+ui.Accent("Spot")+"  ") }
	spots := walkSpots(ctx, readLines(os.Stdin), prompt, probe.ReadWifi, time.Second, func(name string, dbms []int) {
		var v []float64
		for _, d := range dbms {
			v = append(v, float64(d))
		}
		ui.Live("  " + ui.Dim(fmt.Sprintf("measuring %d/%d  ", len(dbms), walkSamples)) + ui.SignalBars(v) + "  " + ui.Dim(fmt.Sprintf("%d dBm", dbms[len(dbms)-1])))
	})
	ui.Live("")
	fmt.Fprintln(promptOut)
	if ctx.Err() != nil {
		ui.Println("  " + ui.Dim("Stopped."))
	}
	ui.Println("")
	ui.Open("Spots")
	for _, row := range walkRows(spots) {
		ui.Println(row)
	}
	st, msg := walkVerdict(spots)
	ui.Verdict(st, msg)
	ui.Println("")
	if asJSON {
		if spots == nil {
			spots = []walkSpot{}
		}
		printJSON(struct {
			Spots   []walkSpot `json:"spots"`
			Verdict verdict    `json:"verdict"`
		}{spots, verdict{st.String(), msg}})
	}
	return 0
}
