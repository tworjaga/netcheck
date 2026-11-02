package ui

import (
	"strings"
	"testing"
)

func fullMenuItems() []Item {
	return []Item{
		{Name: "Doctor", Desc: "full check with a plain-English verdict", Ready: true, Usage: "netcheck doctor [--fast]",
			About: "Runs the checks that matter in parallel: your router, Wi-Fi, the internet, DNS, IPv6, NAT and a speed test."},
		{Name: "Speed", Desc: "throughput and bufferbloat", Ready: true, Usage: "netcheck speed [-t 8s]"},
		{Name: "Ping", Desc: "latency, jitter, packet loss", Ready: true},
		{Name: "Watch", Desc: "live monitor", Ready: true},
		{Name: "DNS", Desc: "resolver comparison", Ready: true},
		{Name: "Devices", Desc: "who is on your network", Ready: true},
		{Name: "Route", Desc: "traceroute", Ready: true},
		{Name: "Wi-Fi", Desc: "signal", Ready: true},
		{Name: "Ports", Desc: "reachability", Ready: true},
		{Name: "More…", Desc: "report, history, …", Ready: true},
	}
}

func TestFullMenuFits(t *testing.T) {
	m := &menuState{items: fullMenuItems()}
	for _, size := range [][2]int{{menuFullW, menuFullH}, {100, 30}, {160, 50}} {
		w, h := size[0], size[1]
		lines := m.renderFull(w, h, "", "192.168.0.123 → 192.168.0.1 → 198.51.100.41 · Example ISP")
		if len(lines) > h {
			t.Errorf("%dx%d: %d lines", w, h, len(lines))
		}
		for i, l := range lines {
			if visWidth(l) > w-1 {
				t.Errorf("%dx%d: line %d is %d wide", w, h, i, visWidth(l))
			}
		}
		screen := strings.Join(lines, "\n")
		for _, want := range []string{"netcheck", "Commands", "❯ Doctor", "Runs the checks that matter", "netcheck doctor [--fast]", "q quit"} {
			if !strings.Contains(screen, want) {
				t.Errorf("%dx%d: missing %q", w, h, want)
			}
		}
	}
}

func TestFullMenuFollowsSelection(t *testing.T) {
	m := &menuState{items: fullMenuItems()}
	m.step(KeyEvent{Key: KeyDown})
	screen := strings.Join(m.renderFull(100, 30, "", ""), "\n")
	if !strings.Contains(screen, "❯ Speed") || !strings.Contains(screen, "Throughput and bufferbloat.") || !strings.Contains(screen, "netcheck speed [-t 8s]") {
		t.Errorf("the side panel describes the selected command:\n%s", screen)
	}
	// In a short window the list scrolls so the selection stays in view.
	for i := 0; i < 8; i++ {
		m.step(KeyEvent{Key: KeyDown})
	}
	short := strings.Join(m.renderFull(80, menuFullH, "", ""), "\n")
	if !strings.Contains(short, "❯ More…") {
		t.Errorf("selection scrolled out of view:\n%s", short)
	}
	m.step(KeyEvent{Key: KeyRune, Rune: '/'})
	m.step(KeyEvent{Key: KeyRune, Rune: 'w'})
	if s := strings.Join(m.renderFull(100, 30, "", ""), "\n"); !strings.Contains(s, "/ w") {
		t.Errorf("search query shown:\n%s", s)
	}
}

func TestMenuModes(t *testing.T) {
	normal := fullMenuItems()
	advanced := []Item{
		{Name: "DNS lookup", Desc: "any record, any server", Ready: false},
		{Name: "Domain audit", Desc: "is my domain set up right", Ready: false},
	}
	m := &menuState{items: normal, modes: []string{"Normal", "Advanced"}, sets: [][]Item{normal, advanced}}
	m.step(KeyEvent{Key: KeyRune, Rune: '/'})
	m.step(KeyEvent{Key: KeyRune, Rune: 'p'})
	m.step(KeyEvent{Key: KeyTab})
	if m.mode != 1 || m.items[0].Name != "DNS lookup" || m.query != "" || m.searching || m.sel != 0 {
		t.Fatalf("tab switches to Advanced with a fresh list: %+v", m)
	}
	if res, _ := m.step(KeyEvent{Key: KeyEnter}); res != stepContinue {
		t.Errorf("a 'soon' item can't be chosen")
	}
	screen := strings.Join(m.renderFull(100, 30, "", ""), "\n")
	for _, want := range []string{"Normal", "Advanced", "tab mode", "DNS lookup · soon", "Not built yet"} {
		if !strings.Contains(screen, want) {
			t.Errorf("full menu missing %q", want)
		}
	}
	if inline := m.render("", ""); !strings.Contains(inline, "Advanced") || !strings.Contains(inline, "tab mode") || !strings.Contains(inline, "soon") {
		t.Errorf("inline menu: %s", inline)
	}
	m.step(KeyEvent{Key: KeyTab})
	if m.mode != 0 || m.items[0].Name != "Doctor" {
		t.Errorf("tab wraps back to Normal")
	}
	single := &menuState{items: normal}
	if single.modeBar() != "" || strings.Contains(single.keyHint(), "tab") {
		t.Errorf("a one-mode menu shows no switch")
	}
}

func TestTabKey(t *testing.T) {
	bytes := []byte{'\t'}
	i := 0
	read := func() (byte, bool) {
		if i >= len(bytes) {
			return 0, false
		}
		i++
		return bytes[i-1], true
	}
	if ev := parseKey(read); ev.Key != KeyTab {
		t.Errorf("unix tab: %+v", ev)
	}
	if ev := translateKey(vkTab, 9, 0); ev.Key != KeyTab {
		t.Errorf("windows tab: %+v", ev)
	}
}
