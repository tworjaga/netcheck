package ui

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Full-screen views: a dashboard that owns the whole window, drawn on the
// terminal's alternate screen so the scrollback is left as it was.

// Size is the window's current width and height (not cached, so a resized
// window is noticed): COLUMNS/LINES if set, else the console's size, else
// 80×24.
func Size() (int, int) {
	w, h := termSize()
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 0 {
		w = c
	}
	if l, err := strconv.Atoi(os.Getenv("LINES")); err == nil && l > 0 {
		h = l
	}
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	return w, h
}

// Box draws a panel exactly w columns wide around lines, padded with empty
// lines to height h (h <= 0: as tall as its content). Lines are cut with
// "…" to fit.
func Box(title string, w, h int, lines []string) []string {
	in := max(1, w-4)
	hor, v := pick("─", "-"), border(pick("│", "|"))
	top := border(pick("╭", "+") + hor)
	if title != "" {
		t := " " + truncate(title, max(1, in-2)) + " "
		top += Bold(t) + border(strings.Repeat(hor, max(0, w-3-visWidth(t)))+pick("╮", "+"))
	} else {
		top += border(strings.Repeat(hor, w-3) + pick("╮", "+"))
	}
	out := []string{top}
	body := max(len(lines), h-2)
	for i := 0; i < body; i++ {
		l := ""
		if i < len(lines) {
			l = truncate(lines[i], in)
		}
		out = append(out, v+" "+l+strings.Repeat(" ", in-visWidth(l))+" "+v)
	}
	return append(out, border(pick("╰", "+")+strings.Repeat(hor, w-2)+pick("╯", "+")))
}

// Beside places blocks of lines next to each other, gap columns apart. Each
// block keeps its own width; shorter blocks are padded with blank lines.
func Beside(gap int, blocks ...[]string) []string {
	widths := make([]int, len(blocks))
	rows := 0
	for i, b := range blocks {
		for _, l := range b {
			widths[i] = max(widths[i], visWidth(l))
		}
		rows = max(rows, len(b))
	}
	out := make([]string, rows)
	for r := range out {
		var sb strings.Builder
		for i, b := range blocks {
			if i > 0 {
				sb.WriteString(strings.Repeat(" ", gap))
			}
			l := ""
			if r < len(b) {
				l = b[r]
			}
			sb.WriteString(l + strings.Repeat(" ", widths[i]-visWidth(l)))
		}
		out[r] = strings.TrimRight(sb.String(), " ")
	}
	return out
}

// Screen is a full-window view on the terminal's alternate screen.
type Screen struct {
	mu sync.Mutex
	on bool
}

// Enter switches to the alternate screen and hides the cursor.
func (s *Screen) Enter() {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Print("\x1b[?1049h\x1b[?25l\x1b[H\x1b[2J")
	s.on = true
}

// Draw replaces the screen's contents with lines, top-left first. Lines
// are cut to the window so nothing wraps.
func (s *Screen) Draw(lines []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.on {
		return
	}
	w, h := Size()
	var b strings.Builder
	b.WriteString("\x1b[H")
	for i, l := range lines {
		if i >= h {
			break
		}
		b.WriteString(truncate(l, w-1) + "\x1b[K")
		if i < min(len(lines), h)-1 {
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\x1b[J")
	fmt.Print(b.String())
}

// Exit restores the normal screen (and its scrollback) and the cursor.
func (s *Screen) Exit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.on {
		fmt.Print("\x1b[?1049l\x1b[?25h")
		s.on = false
	}
}

// Keys reads key presses in the background until ctx ends. ok is false
// when stdin can't do single-key input (a pipe); the caller then relies on
// Ctrl-C alone. The terminal's mode is restored when ctx ends.
func Keys(ctx context.Context) (keys <-chan KeyEvent, ok bool) {
	if !StdinTTY() {
		return nil, false
	}
	restore, err := rawOn()
	if err != nil {
		return nil, false
	}
	ch := make(chan KeyEvent, 8)
	go func() {
		defer restore()
		defer close(ch)
		for ctx.Err() == nil {
			if ev := readKey(); ev.Key != KeyNone {
				select {
				case ch <- ev:
				default:
				}
			}
		}
	}()
	return ch, true
}
