package ui

import (
	"sort"
	"strconv"
	"strings"
)

// Table is a results table for tools that check several targets: a status
// glyph per row, columns sized to their content, a dim header.
type Table struct {
	Headers []string
	Rows    []TableRow
}

// TableRow is one target's results. Cells may be styled (colour doesn't
// count towards widths).
type TableRow struct {
	Status Status
	Cells  []string
}

// Lines renders the table in at most width columns (0: no limit). Columns
// are as wide as their widest cell; the last column is cut to fit.
func (t Table) Lines(width int) []string {
	cols := len(t.Headers)
	for _, r := range t.Rows {
		cols = max(cols, len(r.Cells))
	}
	w := make([]int, cols)
	for i, h := range t.Headers {
		w[i] = visWidth(h)
	}
	for _, r := range t.Rows {
		for i, c := range r.Cells {
			w[i] = max(w[i], visWidth(c))
		}
	}
	line := func(lead string, cells []string, style func(string) string) string {
		var b strings.Builder
		b.WriteString("  " + lead + "  ")
		for i := 0; i < cols; i++ {
			c := ""
			if i < len(cells) {
				c = cells[i]
			}
			if i < cols-1 {
				b.WriteString(style(c) + strings.Repeat(" ", w[i]-visWidth(c)+2))
			} else {
				b.WriteString(style(c))
			}
		}
		s := strings.TrimRight(b.String(), " ")
		if width > 0 {
			s = truncate(s, width)
		}
		return s
	}
	var out []string
	if len(t.Headers) > 0 {
		out = append(out, line(" ", t.Headers, Dim))
	}
	for _, r := range t.Rows {
		out = append(out, line(r.Status.Sym(), r.Cells, func(s string) string { return s }))
	}
	return out
}

// SortBy orders the rows by column col: numbers numerically ("12 ms" before
// "120 ms"), everything else alphabetically, worst status first on ties.
func (t *Table) SortBy(col int, desc bool) {
	key := func(r TableRow) string {
		if col < len(r.Cells) {
			return stripANSI(r.Cells[col])
		}
		return ""
	}
	sort.SliceStable(t.Rows, func(i, j int) bool {
		a, b := key(t.Rows[i]), key(t.Rows[j])
		na, okA := leadingNumber(a)
		nb, okB := leadingNumber(b)
		var less, equal bool
		switch {
		case okA && okB:
			less, equal = na < nb, na == nb
		default:
			less, equal = strings.ToLower(a) < strings.ToLower(b), strings.EqualFold(a, b)
		}
		if equal {
			return statusRank(t.Rows[i].Status) > statusRank(t.Rows[j].Status)
		}
		if desc {
			return !less
		}
		return less
	})
}

// statusRank orders statuses by seriousness.
func statusRank(s Status) int {
	return map[Status]int{OK: 0, Skip: 1, Warn: 2, Bad: 3}[s]
}

func leadingNumber(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || s[end] == '.' || (end == 0 && s[end] == '-')) {
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.ParseFloat(s[:end], 64)
	return n, err == nil
}

// stripANSI removes escape sequences, for sorting and comparing styled text.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			i = skipEscape(s, i)
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
