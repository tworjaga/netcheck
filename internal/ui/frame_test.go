package ui

import (
	"io"
	"os"
	"strings"
	"testing"
)

// capture runs f with stdout redirected and returns what it printed.
func capture(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	return string(b)
}

// panels turns framing on at a fixed width for one test.
func panels(t *testing.T, width int) {
	t.Helper()
	oldOn, oldW, oldQ := framesOn, widthCache, quiet
	framesOn, widthCache, quiet = func() bool { return true }, width, false
	t.Cleanup(func() { framesOn, widthCache, quiet = oldOn, oldW, oldQ; openFrame = false })
}

func TestVisWidthAndTruncate(t *testing.T) {
	s := "\x1b[38;5;114m✓\x1b[0m  192.168.0.1"
	if n := visWidth(s); n != 14 {
		t.Errorf("visWidth = %d, want 14", n)
	}
	if got := truncate("abcdefghij", 6); got != "abcde…" || visWidth(got) != 6 {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate(s, 5); visWidth(got) != 5 || !strings.HasPrefix(got, "\x1b[38;5;114m✓") {
		t.Errorf("escapes must survive a cut: %q", got)
	}
	if truncate("short", 10) != "short" {
		t.Error("short text is left alone")
	}
}

func TestWrap(t *testing.T) {
	got := Wrap("Your connection stalls when it's busy: latency jumps by 173 ms under load.", 30)
	want := []string{"Your connection stalls when", "it's busy: latency jumps by", "173 ms under load."}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q", got)
	}
	if got := Wrap("a supercalifragilisticexpialidocious b", 10); len(got) != 3 || got[1] != "supercalifragilisticexpialidocious" {
		t.Errorf("long word: %q", got)
	}
}

func TestPanelFramesEverything(t *testing.T) {
	panels(t, 60)
	out := capture(t, func() {
		Open("Connection")
		Println(Row("Gateway", OK, "192.168.0.1", "7.4 ms", Spark([]float64{5, 7, 9, -1, 6})))
		Println(Row("ISP", OK, "EXAMPLE - Example Telecom GmbH with a long tail that won't fit", "", "AS64496 · AT"))
		Close()
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("want top, 2 rows, bottom; got %q", lines)
	}
	if !strings.Contains(lines[0], "╭─ Connection ") || !strings.HasSuffix(lines[0], "╮") || !strings.HasPrefix(lines[3], "  ╰") {
		t.Errorf("borders: %q / %q", lines[0], lines[3])
	}
	for i, l := range lines {
		if visWidth(l) != inner()+6 {
			t.Errorf("line %d is %d wide, want %d: %q", i, visWidth(l), inner()+6, l)
		}
	}
	if !strings.HasPrefix(lines[1], "  │ Gateway") || !strings.Contains(lines[2], "…") {
		t.Errorf("rows: %q", lines[1:3])
	}
}

func TestVerdictCallout(t *testing.T) {
	panels(t, 60)
	out := capture(t, func() {
		Verdict(Warn, "Your connection stalls when it's busy: latency jumps by 173 ms under load (grade D).",
			"SQM settings to try: download 16 Mbps (16000 kbit/s), upload 12 Mbps (12000 kbit/s).")
	})
	lines := strings.Split(strings.Trim(out, "\n"), "\n")
	if len(lines) < 6 {
		t.Fatalf("got %q", lines)
	}
	if !strings.HasPrefix(lines[1], "  │ ! Your connection stalls") || !strings.HasPrefix(lines[2], "  │   ") {
		t.Errorf("headline gets the glyph and a hanging indent: %q", lines[1:3])
	}
	bullet := false
	for _, l := range lines {
		if visWidth(l) != inner()+6 {
			t.Errorf("%d wide: %q", visWidth(l), l)
		}
		if strings.HasPrefix(l, "  │   · SQM settings") {
			bullet = true
		}
	}
	if !bullet {
		t.Errorf("notes are bulleted: %q", lines)
	}
}

func TestVerdictPlainWhenPiped(t *testing.T) {
	oldOn, oldQ := framesOn, quiet
	framesOn, quiet = func() bool { return false }, false
	defer func() { framesOn, quiet = oldOn, oldQ }()
	out := capture(t, func() { Verdict(OK, "DNS is healthy.", "a note") })
	if out != "\n  DNS is healthy.\n  a note\n" {
		t.Errorf("piped output must stay as before: %q", out)
	}
}

func TestSparkAndSignalColours(t *testing.T) {
	old := colorOn
	defer func() { colorOn = old }()
	colorOn = false
	if got := Spark([]float64{10, 20, -1, 30}); visWidth(got) != 4 || !strings.Contains(got, "×") {
		t.Errorf("plain spark: %q", got)
	}
	colorOn = true
	got := Spark([]float64{10, 120, 400, -1})
	for _, c := range []color{cGood, cWarn, cBad} {
		if !strings.Contains(got, paint(c, "x")[:len(paint(c, "x"))-len("x\x1b[0m")]) {
			t.Errorf("spark lacks colour %v: %q", c, got)
		}
	}
	if visWidth(got) != 4 {
		t.Errorf("colour must not change the width: %q", got)
	}
	sig := SignalBars([]float64{-55, -70, -80, 0})
	if visWidth(sig) != 4 || !strings.Contains(sig, "×") {
		t.Errorf("signal bars: %q", sig)
	}
}

func TestLiveLinesFitTheWindow(t *testing.T) {
	// A spinner wider than the window wraps, and \r can't overwrite a wrapped
	// line: each redraw then piles up (seen in a 60-column pane).
	old := widthCache
	widthCache = 40
	defer func() { widthCache = old }()
	long := "  Measuring   ⠋  router, internet, DNS, Wi-Fi, IPv6, NAT, speed…"
	if got := fit(long); visWidth(got) != 39 || !strings.HasSuffix(got, "…") {
		t.Errorf("got %d wide: %q", visWidth(got), got)
	}
	if got := fit("  short"); got != "  short" {
		t.Errorf("short lines are left alone: %q", got)
	}
}
