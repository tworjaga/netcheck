package ui

import "testing"

func TestPadIgnoresColorCodes(t *testing.T) {
	old := colorOn
	colorOn = true
	defer func() { colorOn = old }()
	if got := Pad(Dim("Status"), 10); VisWidth(got) != 10 {
		t.Errorf("Pad: %q is %d columns", got, VisWidth(got))
	}
	if got := PadL(Bold("125 ms"), 8); VisWidth(got) != 8 || got[:2] != "  " {
		t.Errorf("PadL: %q", got)
	}
}
