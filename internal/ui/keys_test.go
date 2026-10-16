package ui

import "testing"

func feed(s string) func() (byte, bool) {
	i := 0
	return func() (byte, bool) {
		if i >= len(s) {
			return 0, false // timeout
		}
		i++
		return s[i-1], true
	}
}

func TestParseKey(t *testing.T) {
	cases := []struct {
		in   string
		want KeyEvent
	}{
		{"\x1b[A", KeyEvent{Key: KeyUp}},
		{"\x1b[B", KeyEvent{Key: KeyDown}},
		{"\x1bOA", KeyEvent{Key: KeyUp}},
		{"\x1b[1;5B", KeyEvent{Key: KeyDown}},
		{"\x1b", KeyEvent{Key: KeyEsc}}, // bare Esc: the follow-up read times out
		{"\r", KeyEvent{Key: KeyEnter}},
		{"\n", KeyEvent{Key: KeyEnter}},
		{"\x03", KeyEvent{Key: KeyCtrlC}},
		{"\x7f", KeyEvent{Key: KeyBackspace}},
		{"q", KeyEvent{Key: KeyRune, Rune: 'q'}},
		{"", KeyEvent{}},
		{"\x1b[C", KeyEvent{}}, // right arrow: ignored
	}
	for _, c := range cases {
		if got := parseKey(feed(c.in)); got != c.want {
			t.Errorf("parseKey(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestTranslateWindowsKeys(t *testing.T) {
	cases := []struct {
		vk, ch uint16
		ctrl   uint32
		want   KeyEvent
	}{
		{vkUp, 0, 0, KeyEvent{Key: KeyUp}},
		{vkDown, 0, 0, KeyEvent{Key: KeyDown}},
		{vkReturn, '\r', 0, KeyEvent{Key: KeyEnter}},
		{vkEscape, 0x1b, 0, KeyEvent{Key: KeyEsc}},
		{vkBack, 8, 0, KeyEvent{Key: KeyBackspace}},
		{vkC, 3, ctrlPressedMask, KeyEvent{Key: KeyCtrlC}},
		{vkC, 0, ctrlPressedMask, KeyEvent{Key: KeyCtrlC}},
		{0x51, 'q', 0, KeyEvent{Key: KeyRune, Rune: 'q'}},
		{0x10, 0, 0, KeyEvent{}}, // shift on its own
	}
	for _, c := range cases {
		if got := translateKey(c.vk, c.ch, c.ctrl); got != c.want {
			t.Errorf("translateKey(%#x,%d) = %+v, want %+v", c.vk, c.ch, got, c.want)
		}
	}
}

func testItems() []Item {
	return []Item{{Name: "Doctor", Ready: true}, {Name: "Speed", Ready: true}, {Name: "Ping", Ready: true}}
}

func press(m *menuState, evs ...KeyEvent) (int, int) {
	res, choice := stepContinue, -1
	for _, e := range evs {
		res, choice = m.step(e)
	}
	return res, choice
}

func r(c rune) KeyEvent { return KeyEvent{Key: KeyRune, Rune: c} }

func TestMenuNavigationAndSelect(t *testing.T) {
	m := &menuState{items: testItems()}
	if res, c := press(m, KeyEvent{Key: KeyDown}, KeyEvent{Key: KeyDown}, KeyEvent{Key: KeyEnter}); res != stepChoose || c != 2 {
		t.Fatalf("got (%d,%d)", res, c)
	}
	m = &menuState{items: testItems()}
	if res, c := press(m, KeyEvent{Key: KeyUp}, KeyEvent{Key: KeyEnter}); res != stepChoose || c != 2 {
		t.Fatalf("up from the top should wrap to the last item, got (%d,%d)", res, c)
	}
	m = &menuState{items: testItems()}
	if res, c := press(m, r('j'), r('k'), r('j'), KeyEvent{Key: KeyEnter}); res != stepChoose || c != 1 {
		t.Fatalf("vim keys: got (%d,%d)", res, c)
	}
}

func TestMenuQuit(t *testing.T) {
	for _, ev := range []KeyEvent{r('q'), {Key: KeyEsc}, {Key: KeyCtrlC}} {
		m := &menuState{items: testItems()}
		if res, _ := press(m, ev); res != stepQuit {
			t.Errorf("%+v should quit", ev)
		}
	}
}

func TestMenuSearch(t *testing.T) {
	m := &menuState{items: testItems()}
	if res, _ := press(m, r('/'), r('p'), r('i')); res != stepContinue {
		t.Fatal("search should keep going")
	}
	if v := m.visible(); len(v) != 1 || m.items[v[0]].Name != "Ping" {
		t.Fatalf("filter failed: %v", v)
	}
	if res, c := press(m, KeyEvent{Key: KeyEnter}); res != stepChoose || m.items[c].Name != "Ping" {
		t.Fatalf("enter on filtered list: (%d,%d)", res, c)
	}
	m = &menuState{items: testItems()}
	press(m, r('/'), r('q'))
	if m.query != "q" {
		t.Fatalf("q must be typed while searching, got %q", m.query)
	}
	if res, _ := press(m, KeyEvent{Key: KeyEsc}); res != stepContinue || m.query != "" {
		t.Fatal("esc should clear the search")
	}
	if res, _ := press(m, KeyEvent{Key: KeyEsc}); res != stepQuit {
		t.Fatal("second esc should quit")
	}
}
