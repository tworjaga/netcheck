package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Item is one row of a menu.
type Item struct {
	Name  string
	Desc  string
	Ready bool
	Usage string // shown under the description in the full-screen menu
	About string // a sentence or two on what it checks
}

// StdinTTY reports whether stdin is an interactive terminal.
func StdinTTY() bool { return IsTTY(os.Stdin) }

// menuState is the menu's pure logic: feed it key events, read back what to
// draw. Keeping it free of I/O makes it testable.
type menuState struct {
	items     []Item
	sel       int
	query     string
	searching bool
	// modes and sets, when there's more than one, are switched with Tab:
	// sets[mode] is the item list shown for modes[mode].
	modes []string
	sets  [][]Item
	mode  int
}

// switchMode moves to the next mode, starting its list from the top.
func (m *menuState) switchMode() {
	if len(m.sets) < 2 {
		return
	}
	m.mode = (m.mode + 1) % len(m.sets)
	m.items, m.sel, m.query, m.searching = m.sets[m.mode], 0, "", false
}

// modeBar is "Normal │ Advanced" with the current mode lit, or "" for a
// menu with one mode.
func (m *menuState) modeBar() string {
	if len(m.modes) < 2 {
		return ""
	}
	var parts []string
	for i, name := range m.modes {
		if i == m.mode {
			parts = append(parts, Bold(Accent(name)))
		} else {
			parts = append(parts, Dim(name))
		}
	}
	return strings.Join(parts, Dim(" "+pick("│", "|")+" "))
}

// keyHint is the bottom line of the menu.
func (m *menuState) keyHint() string {
	h := pick("↑↓", "up/down") + " move   ⏎ select   / search"
	if len(m.modes) > 1 {
		h += "   tab mode"
	}
	return h + "   q quit"
}

const (
	stepContinue = iota
	stepChoose
	stepQuit
)

func (m *menuState) visible() []int {
	q := strings.ToLower(m.query)
	var idx []int
	for i, it := range m.items {
		if q == "" || strings.Contains(strings.ToLower(it.Name), q) {
			idx = append(idx, i)
		}
	}
	return idx
}

func (m *menuState) move(d int) {
	if n := len(m.visible()); n > 0 {
		m.sel = (m.sel + d + n) % n
	}
}

// step applies one key event. On stepChoose, choice indexes items.
func (m *menuState) step(ev KeyEvent) (result, choice int) {
	vis := m.visible()
	switch ev.Key {
	case KeyCtrlC:
		return stepQuit, -1
	case KeyUp:
		m.move(-1)
	case KeyDown:
		m.move(1)
	case KeyEnter:
		// Items marked "soon" are shown but can't run yet.
		if len(vis) > 0 && m.items[vis[min(m.sel, len(vis)-1)]].Ready {
			return stepChoose, vis[min(m.sel, len(vis)-1)]
		}
	case KeyTab:
		m.switchMode()
	case KeyEsc:
		if m.searching || m.query != "" {
			m.searching, m.query, m.sel = false, "", 0
		} else {
			return stepQuit, -1
		}
	case KeyBackspace:
		if m.searching {
			if m.query == "" {
				m.searching = false
			} else {
				m.query = m.query[:len(m.query)-1]
			}
			m.sel = 0
		}
	case KeyRune:
		switch {
		case m.searching:
			m.query += string(ev.Rune)
			m.sel = 0
		case ev.Rune == 'q':
			return stepQuit, -1
		case ev.Rune == 'k':
			m.move(-1)
		case ev.Rune == 'j':
			m.move(1)
		case ev.Rune == '/':
			m.searching = true
		}
	}
	m.sel = max(0, min(m.sel, max(0, len(m.visible())-1)))
	return stepContinue, -1
}

func (m *menuState) render(title, summary string) string {
	var b strings.Builder
	b.WriteString("\n  " + Bold("netcheck"))
	if title != "" {
		b.WriteString("  " + Dim(title))
	}
	if bar := m.modeBar(); bar != "" {
		b.WriteString("    " + bar)
	}
	b.WriteString("\n\n")
	if summary != "" {
		b.WriteString("  " + Dim(summary) + "\n\n")
	}
	vis := m.visible()
	for pos, i := range vis {
		it := m.items[i]
		name, desc := pad(it.Name, 16), it.Desc
		if !it.Ready {
			desc += " · soon"
		}
		switch {
		case pos == m.sel && it.Ready:
			b.WriteString("  " + Accent(pick("❯", ">")) + " " + Bold(Accent(name)) + Dim(desc) + "\n")
		case pos == m.sel:
			b.WriteString("  " + Accent(pick("❯", ">")) + " " + Dim(name+desc) + "\n")
		case it.Ready:
			b.WriteString("    " + name + Dim(desc) + "\n")
		default:
			b.WriteString("    " + Dim(name+desc) + "\n")
		}
	}
	if len(vis) == 0 {
		b.WriteString("    " + Dim("no match") + "\n")
	}
	b.WriteString("\n")
	if m.searching {
		b.WriteString("  " + Accent("/") + " " + m.query + Dim("▏") + Dim("    esc clear   ⏎ select") + "\n")
	} else {
		b.WriteString("  " + Dim(m.keyHint()) + "\n")
	}
	return b.String()
}

// Menu shows a menu and returns the chosen index, or -1 on quit. Arrow keys
// or j/k move, Enter selects, "/" filters, q or Esc quits. summary is polled
// so slow lookups (public IP, ISP) can appear after the menu is already up.
func Menu(title string, summary func() string, items []Item, start int) int {
	_, choice := MenuModes(title, summary, nil, [][]Item{items}, 0, start)
	return choice
}

// MenuModes is Menu with several modes (such as Normal and Advanced), each
// with its own items, switched with Tab. It returns the mode showing when
// the menu closed and the chosen index in that mode's items (-1 on quit).
func MenuModes(title string, summary func() string, modes []string, sets [][]Item, mode, start int) (int, int) {
	mode = max(0, min(mode, len(sets)-1))
	restore, err := rawOn()
	if err != nil {
		return mode, menuFallback(summary(), sets[mode])
	}
	defer restore()
	m := &menuState{items: sets[mode], sel: start, modes: modes, sets: sets, mode: mode}
	choice := menuRun(m, title, summary)
	return m.mode, choice
}

// menuRun runs the menu full screen when the window allows, else inline.
func menuRun(m *menuState, title string, summary func() string) int {
	if w, h := Size(); w >= menuFullW && h >= menuFullH {
		return menuFull(m, title, summary)
	}
	fmt.Print("\x1b[?25l")
	defer fmt.Print("\x1b[?25h")

	lines := 0
	last := ""
	clear := func() {
		if lines > 0 {
			fmt.Printf("\x1b[%dA\r\x1b[J", lines)
			lines = 0
		}
	}
	draw := func() {
		clear()
		last = summary()
		out := m.render(title, last)
		fmt.Print(out)
		lines = strings.Count(out, "\n")
	}
	draw()
	for {
		ev := readKey()
		if ev.Key == KeyNone {
			if summary() != last {
				draw()
			}
			continue
		}
		switch res, choice := m.step(ev); res {
		case stepQuit:
			clear()
			return -1
		case stepChoose:
			clear()
			return choice
		}
		draw()
	}
}

// menuFallback is a numbered prompt for terminals without single-key input.
func menuFallback(summary string, items []Item) int {
	fmt.Println("\n  " + Bold("netcheck") + "\n")
	if summary != "" {
		fmt.Println("  " + Dim(summary) + "\n")
	}
	for i, it := range items {
		desc := it.Desc
		if !it.Ready {
			desc += " · soon"
		}
		fmt.Printf("  %2d  %s%s\n", i+1, pad(it.Name, 16), Dim(desc))
	}
	fmt.Printf("\n  choose 1-%d (q to quit): ", len(items))
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(items) {
		return -1
	}
	return n - 1
}

// WaitKey shows prompt and waits for a key. It returns false on q or Ctrl-C.
func WaitKey(prompt string) bool {
	restore, err := rawOn()
	if err != nil {
		fmt.Print("\n  " + Dim(prompt+" (enter / q) "))
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "q")
	}
	defer restore()
	fmt.Print("\n  " + Dim(prompt))
	for {
		ev := readKey()
		if ev.Key == KeyNone {
			continue
		}
		fmt.Print("\r\x1b[2K")
		return ev.Key != KeyCtrlC && !(ev.Key == KeyRune && ev.Rune == 'q')
	}
}

// Full-screen menu sizes: below these the inline menu is used.
const (
	menuFullW = 70
	menuFullH = 18
)

// renderFull draws the menu filling a w×h window: the commands on the left,
// what the selected one does on the right, the network path on top and the
// keys at the bottom.
func (m *menuState) renderFull(w, h int, title, summary string) []string {
	head := " " + Bold("netcheck")
	if title != "" {
		head += "  " + Dim(title)
	}
	if bar := m.modeBar(); bar != "" {
		head += "    " + bar
	}
	out := []string{head, " " + Dim(summary), ""}

	vis := m.visible()
	listW := 24
	for _, it := range m.items {
		listW = max(listW, visWidth(it.Name)+6)
	}
	paneW := w - 2 - listW - 1
	boxH := max(6, h-len(out)-2)

	var list []string
	for pos, i := range vis {
		it := m.items[i]
		switch {
		case pos == m.sel && it.Ready:
			list = append(list, Accent(pick("❯", ">"))+" "+Bold(Accent(it.Name)))
		case pos == m.sel:
			list = append(list, Accent(pick("❯", ">"))+" "+Dim(it.Name+" · soon"))
		case it.Ready:
			list = append(list, "  "+it.Name)
		default:
			list = append(list, "  "+Dim(it.Name+" · soon"))
		}
	}
	if len(vis) == 0 {
		list = append(list, Dim("no match"))
	}
	// Keep the selection in view in a short window.
	if inside := boxH - 2; len(list) > inside && m.sel >= inside {
		list = list[m.sel-inside+1:]
	}

	paneTitle, pane := "", []string{}
	if len(vis) > 0 {
		it := m.items[vis[m.sel]]
		paneTitle = it.Name
		text := it.About
		if text == "" {
			text = upper(it.Desc) + "."
		}
		pane = append(pane, Wrap(text, paneW-4)...)
		switch {
		case !it.Ready:
			pane = append(pane, "", Dim("Not built yet: arriving step by step (docs/TODO.md)."))
		case it.Usage != "":
			pane = append(pane, "", Dim(it.Usage))
		}
	}
	for _, l := range Beside(1, Box("Commands", listW, boxH, list), Box(paneTitle, paneW, boxH, pane)) {
		out = append(out, " "+l)
	}

	keys := strings.Replace(m.keyHint(), "⏎ select", "⏎ run", 1)
	if m.searching {
		keys = "/ " + m.query + "▏   esc clear   ⏎ run"
	}
	out = append(out, " "+Dim(keys))
	for i, l := range out {
		out[i] = truncate(l, w-1)
	}
	return out
}

func upper(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// menuFull runs the menu on the alternate screen. It redraws on every key,
// when the summary changes (the public IP arriving) and when the window is
// resized; it leaves the screen before returning, so the chosen command
// prints into the normal scrollback.
func menuFull(m *menuState, title string, summary func() string) int {
	var scr Screen
	scr.Enter()
	defer scr.Exit()
	last, lw, lh := "", 0, 0
	draw := func() {
		w, h := Size()
		last, lw, lh = summary(), w, h
		scr.Draw(m.renderFull(w, h, title, last))
	}
	draw()
	for {
		ev := readKey()
		if ev.Key == KeyNone {
			if w, h := Size(); summary() != last || w != lw || h != lh {
				draw()
			}
			continue
		}
		switch res, choice := m.step(ev); res {
		case stepQuit:
			return -1
		case stepChoose:
			return choice
		}
		draw()
	}
}
