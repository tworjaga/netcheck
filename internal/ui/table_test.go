package ui

import (
	"strings"
	"testing"
)

func TestTableLines(t *testing.T) {
	old := colorOn
	colorOn = false
	defer func() { colorOn = old }()
	tb := Table{
		Headers: []string{"Target", "State", "Time"},
		Rows: []TableRow{
			{OK, []string{"db.lan:5432", "open", "120 ms"}},
			{Bad, []string{"redis.lan:6379", Alert("filtered"), "–"}},
			{Warn, []string{"api.example.com:443", "open", "12 ms"}},
		},
	}
	lines := tb.Lines(0)
	if len(lines) != 4 {
		t.Fatalf("header + 3 rows: %q", lines)
	}
	// Columns line up: "State" starts at the same place in every line.
	col := visWidth(lines[0][:strings.Index(lines[0], "State")])
	for _, l := range lines[1:] {
		if i := strings.Index(l, "open"); i >= 0 && visWidth(l[:i]) != col {
			t.Errorf("misaligned: %q", l)
		}
	}
	if !strings.HasPrefix(lines[2], "  ✗  redis.lan:6379") {
		t.Errorf("status glyph first: %q", lines[2])
	}
	tb.SortBy(2, false)
	if !strings.Contains(tb.Rows[0].Cells[0], "api.example.com") || !strings.Contains(tb.Rows[1].Cells[0], "db.lan") {
		t.Errorf("12 ms sorts before 120 ms, '–' after numbers: %+v", tb.Rows)
	}
	tb.Rows = append(tb.Rows, TableRow{Bad, []string{"web.lan:80", "open", "12 ms"}})
	tb.SortBy(2, false)
	if !strings.Contains(tb.Rows[0].Cells[0], "web.lan") {
		t.Errorf("on a tie the worse status comes first: %+v", tb.Rows)
	}
	for _, l := range tb.Lines(30) {
		if visWidth(l) > 30 {
			t.Errorf("cut to the width: %q", l)
		}
	}
}
