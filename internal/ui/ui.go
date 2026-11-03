// Package ui is netcheck's tiny presentation layer: one accent color, dim
// secondary text, aligned rows, sparklines and spinners that resolve into
// result lines. Standard library only.
package ui

import (
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"
)

// Status is the outcome of a single check.
type Status int

const (
	OK Status = iota
	Warn
	Bad
	Skip
)

func (s Status) String() string {
	switch s {
	case OK:
		return "ok"
	case Warn:
		return "warn"
	case Bad:
		return "bad"
	}
	return "skip"
}

type color struct {
	r, g, b uint8
	idx     int // 256-color fallback
}

var (
	cAccent = color{122, 162, 247, 111}
	cDim    = color{107, 114, 128, 244}
	cGood   = color{158, 206, 106, 114}
	cWarn   = color{224, 175, 104, 179}
	cBad    = color{247, 118, 142, 211}
)

var (
	colorOn   bool
	trueColor bool
	ttyOut    bool
	asciiOnly bool
	quiet     bool
)

func init() {
	ttyOut = IsTTY(os.Stdout)
	_, noColor := os.LookupEnv("NO_COLOR")
	colorOn = ttyOut && !noColor && os.Getenv("TERM") != "dumb"
	ct := os.Getenv("COLORTERM")
	trueColor = ct == "truecolor" || ct == "24bit"
	asciiOnly = os.Getenv("NETCHECK_ASCII") != ""
	enableVT()
}

// IsTTY reports whether f is an interactive terminal.
func IsTTY(f *os.File) bool { return isTerminal(f) }

// Interactive reports whether stdout is a terminal.
func Interactive() bool { return ttyOut }

// SetQuiet silences all decorative output (used for --json).
func SetQuiet(q bool) { quiet = q }

// SetPlain turns off colors and terminal tricks (output going to a log).
func SetPlain() { colorOn, ttyOut = false, false }

func paint(c color, s string) string {
	if !colorOn || s == "" {
		return s
	}
	if trueColor {
		return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[0m", c.r, c.g, c.b, s)
	}
	return fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", c.idx, s)
}

func Accent(s string) string  { return paint(cAccent, s) }
func Dim(s string) string     { return paint(cDim, s) }
func Good(s string) string    { return paint(cGood, s) }
func Caution(s string) string { return paint(cWarn, s) }
func Alert(s string) string   { return paint(cBad, s) }

func Bold(s string) string {
	if !colorOn || s == "" {
		return s
	}
	return "\x1b[1m" + s + "\x1b[0m"
}

// Paint colors text by status.
func (s Status) Paint(txt string) string {
	switch s {
	case OK:
		return Good(txt)
	case Warn:
		return Caution(txt)
	case Bad:
		return Alert(txt)
	}
	return Dim(txt)
}

func pick(uni, asc string) string {
	if asciiOnly {
		return asc
	}
	return uni
}

// Sym is the colored status glyph.
func (s Status) Sym() string {
	switch s {
	case OK:
		return Good(pick("✓", "+"))
	case Warn:
		return Caution("!")
	case Bad:
		return Alert(pick("✗", "x"))
	}
	return Dim(pick("–", "-"))
}

// Spark renders a latency sparkline (ms), each bar coloured by how good
// that sample is. Negative values are lost probes.
func Spark(ms []float64) string { return spark(ms, latencyColor) }

// Trend is a sparkline for anything that isn't latency (throughput, say),
// in the plain accent colour.
func Trend(vals []float64) string {
	return spark(vals, func(float64) color { return cAccent })
}

func spark(ms []float64, colour func(float64) color) string {
	set := []rune("▁▂▃▄▅▆▇█")
	if asciiOnly {
		set = []rune("_.-~=+*#")
	}
	lo, hi := math.Inf(1), 0.0
	for _, v := range ms {
		if v < 0 {
			continue
		}
		lo = min(lo, v)
		hi = max(hi, v)
	}
	if math.IsInf(lo, 1) {
		lo = 0
	}
	// Keep a floor on the range so a steady line stays low instead of
	// stretching tiny jitter into tall bars.
	top := math.Max(hi, math.Max(lo*1.5, lo+2))

	var c cells
	for _, v := range ms {
		if v < 0 {
			c.add(cBad, []rune(pick("×", "x"))[0])
			continue
		}
		i := int((v-lo)/(top-lo)*float64(len(set)-1) + 0.5)
		i = max(0, min(len(set)-1, i))
		c.add(colour(v), set[i])
	}
	return c.String()
}

// latencyColor rates one latency sample: green up to 60 ms, amber up to
// 150 ms (where calls start to suffer), red above.
func latencyColor(ms float64) color {
	switch {
	case ms <= 60:
		return cGood
	case ms <= 150:
		return cWarn
	}
	return cBad
}

// cells builds a run of coloured glyphs, one escape per colour change.
type cells struct {
	b    strings.Builder
	run  []rune
	cur  color
	some bool
}

func (c *cells) add(col color, r rune) {
	if c.some && col != c.cur {
		c.flush()
	}
	c.cur, c.some = col, true
	c.run = append(c.run, r)
}

func (c *cells) flush() {
	if len(c.run) > 0 {
		c.b.WriteString(paint(c.cur, string(c.run)))
		c.run = c.run[:0]
	}
}

func (c *cells) String() string {
	c.flush()
	return c.b.String()
}

// labelW is the width of the label column in result rows and spinners.
const labelW = 12

// width is the printed columns: color codes take none.
func width(s string) int { return visWidth(s) }

func pad(s string, w int) string {
	if n := width(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

func padL(s string, w int) string {
	if n := width(s); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return s
}

// Row formats one aligned result line. extra is used verbatim, so callers
// can pass pre-styled text (a sparkline, dim notes).
func Row(label string, st Status, target, metric, extra string) string {
	m := padL(metric, 8)
	if st == Warn || st == Bad {
		m = st.Paint(m)
	}
	line := "  " + pad(label, labelW) + st.Sym() + "  " + pad(target, 18) + " " + m
	return Detail(line, extra, labelW+3)
}

// Println prints unless quiet.
func Println(s string) {
	if !quiet {
		fmt.Println(framed(s))
	}
}

// Title prints the tool name once, with an optional dim subtitle.
func Title(sub string) {
	if quiet {
		return
	}
	line := "\n  " + Bold("netcheck")
	if sub != "" {
		line += "  " + Dim(sub)
	}
	fmt.Println(line + "\n")
}

// Live rewrites the current terminal line (no-op when not interactive).
func Live(s string) {
	if quiet || !ttyOut {
		return
	}
	fmt.Print("\r\x1b[2K" + fit(s))
}

// LiveEnd finishes a live line with its final text.
func LiveEnd(s string) {
	if quiet {
		return
	}
	if ttyOut {
		fmt.Print("\r\x1b[2K")
	}
	fmt.Println(framed(s))
}

// Task is a spinner row that resolves into a result line.
type Task struct {
	label string
	mu    sync.Mutex
	text  string
	stop  chan struct{}
	done  chan struct{}
	live  bool
}

// Begin starts a spinner for label. Call Finish exactly once.
func Begin(label string) *Task {
	t := &Task{label: label, stop: make(chan struct{}), done: make(chan struct{})}
	if ttyOut && !quiet {
		t.live = true
		go t.spin()
	} else {
		close(t.done)
	}
	return t
}

func (t *Task) spin() {
	defer close(t.done)
	frames := spinnerFrames()
	tick := time.NewTicker(80 * time.Millisecond)
	defer tick.Stop()
	for i := 0; ; i++ {
		t.mu.Lock()
		txt := t.text
		t.mu.Unlock()
		fmt.Print("\r\x1b[2K" + fit("  "+pad(t.label, labelW)+Accent(frames[i%len(frames)])+"  "+txt))
		select {
		case <-t.stop:
			return
		case <-tick.C:
		}
	}
}

// Progress updates the text shown next to the spinner.
func (t *Task) Progress(s string) {
	t.mu.Lock()
	t.text = s
	t.mu.Unlock()
}

// Finish stops the spinner and prints the final line.
func (t *Task) Finish(line string) {
	if t.live {
		close(t.stop)
		<-t.done
		fmt.Print("\r\x1b[2K")
	}
	Println(line)
}

// Bars renders values on a fixed scale from lo (lowest bar) to hi (tallest),
// unlike Spark, which stretches to the data. A value <= missing renders as a
// gap mark (×), for readings that failed.
func Bars(vals []float64, lo, hi, missing float64) string {
	return bars(vals, lo, hi, missing, func(float64) color { return cAccent })
}

// LatencyBars is Bars for latency (ms): each bar coloured green, amber or
// red like Spark, on a scale shared by several strips.
func LatencyBars(vals []float64, lo, hi, missing float64) string {
	return bars(vals, lo, hi, missing, latencyColor)
}

func bars(vals []float64, lo, hi, missing float64, colour func(float64) color) string {
	set := []rune("▁▂▃▄▅▆▇█")
	if asciiOnly {
		set = []rune("_.-~=+*#")
	}
	var c cells
	for _, v := range vals {
		if v <= missing {
			c.add(cBad, []rune(pick("×", "x"))[0])
			continue
		}
		i := int((v-lo)/(hi-lo)*float64(len(set)-1) + 0.5)
		c.add(colour(v), set[max(0, min(len(set)-1, i))])
	}
	return c.String()
}

// Clear stops the spinner and removes its line without printing a result.
func (t *Task) Clear() {
	if t.live {
		close(t.stop)
		<-t.done
		fmt.Print("\r\x1b[2K")
	}
}

// Pad right-pads s with spaces to w columns (for hand-built aligned lines).
func Pad(s string, w int) string { return pad(s, w) }

// Block is a multi-line region that redraws in place on a terminal, such as
// a live route table. When output isn't a terminal, only End prints.
type Block struct{ lines int }

func (b *Block) erase() {
	if b.lines > 0 {
		fmt.Printf("\x1b[%dA\r\x1b[J", b.lines)
		b.lines = 0
	}
}

// Update replaces the block's contents (no-op unless on a terminal).
func (b *Block) Update(lines []string) {
	if quiet || !ttyOut {
		return
	}
	b.erase()
	n := 0
	for _, l := range lines {
		// A line may hold several rows (a result row whose details moved
		// to a line of their own); count what's actually on screen.
		for _, row := range strings.Split(l, "\n") {
			fmt.Println(fit(row))
			n++
		}
	}
	b.lines = n
}

// End replaces the block with its final contents and stops tracking it.
func (b *Block) End(lines []string) {
	if !quiet {
		if ttyOut {
			b.erase()
		}
		for _, l := range lines {
			fmt.Println(framed(l))
		}
	}
	b.lines = 0
}

// Gap is a dim dot for a slot with no data, as in a per-hour strip.
func Gap() string { return Dim(pick("·", ".")) }

func spinnerFrames() []string {
	if asciiOnly {
		return []string{"|", "/", "-", "\\"}
	}
	return []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
}

// SignalBars renders Wi-Fi signal readings (dBm) on a fixed -90 to -40 scale,
// each bar coloured by quality: green from -67 dBm (good), amber down to
// -75 (fair), red below. A reading of 0 (not connected) is a gap mark.
func SignalBars(dbm []float64) string {
	set := []rune("▁▂▃▄▅▆▇█")
	if asciiOnly {
		set = []rune("_.-~=+*#")
	}
	var c cells
	for _, v := range dbm {
		if v == 0 || v <= -150 {
			c.add(cBad, []rune(pick("×", "x"))[0])
			continue
		}
		i := int((v+90)/50*float64(len(set)-1) + 0.5)
		col := cGood
		switch {
		case v < -75:
			col = cBad
		case v < -67:
			col = cWarn
		}
		c.add(col, set[max(0, min(len(set)-1, i))])
	}
	return c.String()
}

// PadL right-aligns s in w printed columns.
func PadL(s string, w int) string { return padL(s, w) }
