package ui

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Panels: rounded frames around groups of result lines, drawn only on a
// terminal. Commands open a panel, print as usual (rows, spinners, live
// lines all land inside it), and close it. Piped and --json output never
// sees a frame, so it stays exactly as plain as before.

var (
	frameMu    sync.Mutex
	framesOn   = func() bool { return ttyOut && !quiet }
	openFrame  bool
	widthCache int
)

// maxPanel caps a panel's total width, so wide terminals don't stretch
// rows into a thin line across the screen.
const maxPanel = 100

// Width is the terminal's width in columns: COLUMNS if set, else the
// console's own size, else 80.
func Width() int {
	if widthCache > 0 {
		return widthCache
	}
	w := 0
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 0 {
		w = c
	} else if c, _ := termSize(); c > 0 {
		w = c
	}
	if w <= 0 {
		w = 80
	}
	widthCache = w
	return w
}

// inner is the text width inside a panel: "  │ " + text + " │".
func inner() int {
	return max(20, min(Width()-1, maxPanel)-6)
}

// visWidth is the printed width of s, ignoring ANSI escape sequences.
func visWidth(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			i = skipEscape(s, i)
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n++
	}
	return n
}

// skipEscape returns the index just past the CSI sequence starting at i.
func skipEscape(s string, i int) int {
	j := i + 1
	if j < len(s) && s[j] == '[' {
		j++
		for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
			j++
		}
		return min(j+1, len(s))
	}
	return j
}

// truncate shortens s to w printed columns, ending in "…" when cut. Escape
// sequences are kept, and colour is reset after a cut.
func truncate(s string, w int) string {
	if visWidth(s) <= w {
		return s
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			j := skipEscape(s, i)
			b.WriteString(s[i:j])
			i = j
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if n == w-1 {
			b.WriteString(pick("…", "~"))
			if colorOn {
				b.WriteString("\x1b[0m")
			}
			return b.String()
		}
		b.WriteRune(r)
		n++
		i += size
	}
	return b.String()
}

func border(s string) string { return Dim(s) }

// statusBorder colours a callout's frame by its status (dim when skipped).
func statusBorder(st Status) func(string) string {
	return func(s string) string {
		if st == Skip {
			return Dim(s)
		}
		return st.Paint(s)
	}
}

// frameLine puts one line of output inside the open panel: the usual two
// space margin moves outside the frame, and the line is cut or padded to
// the panel's width.
func frameLine(line string) string {
	line = strings.TrimPrefix(line, "  ")
	w := inner()
	line = truncate(line, w)
	return "  " + border(pick("│", "|")) + " " + line + strings.Repeat(" ", w-visWidth(line)) + " " + border(pick("│", "|"))
}

// framed passes s through the open panel, line by line.
func framed(s string) string {
	frameMu.Lock()
	on := openFrame
	frameMu.Unlock()
	if !on {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = frameLine(l)
	}
	return strings.Join(lines, "\n")
}

// topBorder is "╭─ Title ───╮" across the panel.
func topBorder(title string, paintTitle, border func(string) string) string {
	w := inner() + 2
	h, tl, tr := pick("─", "-"), pick("╭", "+"), pick("╮", "+")
	if title == "" {
		return "  " + border(tl+strings.Repeat(h, w)+tr)
	}
	t := " " + title + " "
	rest := max(0, w-1-visWidth(t))
	return "  " + border(tl+h) + paintTitle(t) + border(strings.Repeat(h, rest)+tr)
}

func bottomBorder(border func(string) string) string {
	return "  " + border(pick("╰", "+")+strings.Repeat(pick("─", "-"), inner()+2)+pick("╯", "+"))
}

// Open starts a panel titled title. Everything printed until Close lands
// inside it. Off a terminal it does nothing.
func Open(title string) {
	if !framesOn() {
		return
	}
	Println(topBorder(title, Bold, border))
	frameMu.Lock()
	openFrame = true
	frameMu.Unlock()
}

// Close ends the open panel.
func Close() {
	frameMu.Lock()
	on := openFrame
	openFrame = false
	frameMu.Unlock()
	if on {
		Println(bottomBorder(border))
	}
}

// Wrap breaks text into lines of at most w columns at spaces. A word longer
// than w gets a line of its own.
func Wrap(text string, w int) []string {
	var lines []string
	cur := ""
	for _, word := range strings.Fields(text) {
		switch {
		case cur == "":
			cur = word
		case visWidth(cur)+1+visWidth(word) <= w:
			cur += " " + word
		default:
			lines = append(lines, cur)
			cur = word
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// Verdict prints the answer to a check: a headline and dim supporting
// notes. On a terminal it's a callout panel with a status glyph, wrapped to
// fit; elsewhere it's the plain lines netcheck has always printed.
func Verdict(st Status, head string, notes ...string) {
	if quiet {
		return
	}
	if !framesOn() {
		Println("\n  " + st.Paint(head))
		for _, n := range notes {
			if n != "" {
				Println("  " + Dim(n))
			}
		}
		return
	}
	w := inner()
	var lines []string
	for i, l := range Wrap(head, w-2) {
		lead := "  "
		if i == 0 {
			lead = st.Sym() + " "
		}
		lines = append(lines, lead+st.Paint(l))
	}
	for _, n := range notes {
		for i, l := range Wrap(n, w-4) {
			lead := "    "
			if i == 0 {
				lead = "  " + Dim(pick("·", "-")) + " "
			}
			lines = append(lines, lead+Dim(l))
		}
	}
	Close()
	b := statusBorder(st)
	Println("")
	Println(topBorder("", nil, b))
	for _, l := range lines {
		Println(frameLineIn(l, b))
	}
	Println(bottomBorder(b))
}

// frameLineIn frames a verdict line; the side bars take the status colour
// so the callout reads at a glance.
func frameLineIn(line string, border func(string) string) string {
	w := inner()
	line = truncate(line, w)
	bar := border(pick("│", "|"))
	return "  " + bar + " " + line + strings.Repeat(" ", w-visWidth(line)) + " " + bar
}

// Framed reports whether output is drawn in panels (a terminal, not --json).
func Framed() bool { return framesOn() }

// fit prepares a line that redraws in place (spinners, live lines, blocks).
// Inside a panel it's framed, which already cuts it to fit; outside one it's
// cut to the window, because a line that wraps can't be overwritten with \r
// and every redraw would pile up as a new line.
func fit(s string) string {
	frameMu.Lock()
	on := openFrame
	frameMu.Unlock()
	if on {
		return framed(s)
	}
	return truncate(s, Width()-1)
}

// PanelWidth is the text width inside a panel, for content drawn to fit
// (charts); off a terminal it's the window's width.
func PanelWidth() int {
	if framesOn() {
		return inner()
	}
	return Width() - 2
}

// Detail joins a row and its trailing detail. In a panel too narrow for
// both, the detail moves to a line of its own, indented by indent columns,
// instead of being cut off.
func Detail(row, detail string, indent int) string {
	if detail == "" {
		return row
	}
	if framesOn() && visWidth(row)+2+visWidth(detail)-2 > inner() && visWidth(row)-2 <= inner() {
		return strings.TrimRight(row, " ") + "\n  " + strings.Repeat(" ", indent) + detail
	}
	return row + "  " + detail
}

// VisWidth is the printed width of s; colour codes don't count.
func VisWidth(s string) int { return visWidth(s) }

// Pick chooses the Unicode form, or the ASCII one in NETCHECK_ASCII mode.
func Pick(uni, asc string) string { return pick(uni, asc) }

// Cut shortens s to w printed columns, ending in "…" when cut.
func Cut(s string, w int) string { return truncate(s, w) }
