package adv

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// --fail-on rules turn a check into a pass/fail for scripts: when any rule
// is broken, the tool exits 1. A rule is "metric<value" or "metric>value";
// a bare value applies to the tool's default metric with its natural
// comparison (for certificates, "14d" means "fail if fewer than 14 days
// left"). Several rules are separated by commas.
//
// Values carry units, and tools report measurements in the same base
// units: durations in milliseconds ("14d", "2h", "500ms"), percentages as
// numbers ("1%"), grades A (best) to F, plain numbers as they are.

// Rule is one parsed --fail-on condition.
type Rule struct {
	Metric string  // "" = the tool's default metric
	Op     byte    // '<' or '>'; 0 = the default metric's own direction
	Value  float64 // in base units (ms, %, grade number, plain)
	Text   string  // as written, for messages
}

// grades are ordered best first; a higher number is a better grade.
var grades = map[string]float64{"A+": 7, "A": 6, "A-": 5, "B": 4, "C": 3, "D": 2, "E": 1, "F": 0}

// GradeValue is the number a grade compares as (A+ highest, F lowest).
func GradeValue(g string) (float64, bool) {
	v, ok := grades[strings.ToUpper(strings.TrimSpace(g))]
	return v, ok
}

// ParseValue reads a value with its unit into base units.
func ParseValue(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if g, ok := GradeValue(s); ok && !strings.ContainsAny(s, "0123456789") {
		return g, nil
	}
	if strings.HasSuffix(s, "%") {
		return strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
	}
	units := []struct {
		suffix string
		ms     float64
	}{{"ms", 1}, {"d", 24 * 3600 * 1000}, {"h", 3600 * 1000}, {"m", 60 * 1000}, {"s", 1000}}
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			n, err := strconv.ParseFloat(strings.TrimSuffix(s, u.suffix), 64)
			if err != nil {
				return 0, fmt.Errorf("%q isn't a number of %s", s, u.suffix)
			}
			return n * u.ms, nil
		}
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("%q isn't a value netcheck understands (try 14d, 200ms, 1%%, B)", s)
	}
	return n, nil
}

// ParseRules reads a --fail-on spec such as "14d" or "loss>1%,rtt>200ms".
func ParseRules(spec string) ([]Rule, error) {
	var out []Rule
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		r := Rule{Text: part}
		val := part
		if i := strings.IndexAny(part, "<>"); i >= 0 {
			r.Metric, r.Op, val = strings.ToLower(strings.TrimSpace(part[:i])), part[i], part[i+1:]
			if r.Metric == "" {
				return nil, fmt.Errorf("--fail-on %q: name what to compare, like loss>1%%", part)
			}
		}
		v, err := ParseValue(val)
		if err != nil {
			return nil, fmt.Errorf("--fail-on %q: %w", part, err)
		}
		r.Value = v
		out = append(out, r)
	}
	return out, nil
}

// Default is a tool's main metric and the direction in which it's bad:
// "expiry" with '<' fails when the value drops below the limit.
type Default struct {
	Metric string
	Op     byte
}

// Broken returns the rules a tool's measurements break, with a sentence
// for each. Rules on metrics the tool didn't measure are reported too, so
// a typo can't silently pass.
func Broken(rules []Rule, def Default, got map[string]float64) []string {
	var out []string
	for _, r := range rules {
		metric, op := r.Metric, r.Op
		if metric == "" {
			metric, op = def.Metric, def.Op
		}
		v, ok := got[metric]
		if !ok {
			names := make([]string, 0, len(got))
			for k := range got {
				names = append(names, k)
			}
			sort.Strings(names)
			out = append(out, fmt.Sprintf("%s: this tool doesn't measure %q (it measures %s)", r.Text, metric, strings.Join(names, ", ")))
			continue
		}
		if (op == '<' && v < r.Value) || (op == '>' && v > r.Value) {
			out = append(out, fmt.Sprintf("%s: %s is %s", r.Text, metric, formatLike(v, r.Text)))
		}
	}
	return out
}

// formatLike prints a measurement in the unit the rule was written in.
func formatLike(v float64, text string) string {
	val := text
	if i := strings.IndexAny(text, "<>"); i >= 0 {
		val = text[i+1:]
	}
	val = strings.TrimSpace(val)
	switch {
	case strings.HasSuffix(val, "%"):
		return strconv.FormatFloat(v, 'f', -1, 64) + "%"
	case strings.HasSuffix(val, "ms"):
		return fmt.Sprintf("%.0fms", v)
	case strings.HasSuffix(val, "d"):
		return fmt.Sprintf("%.1fd", v/(24*3600*1000))
	case strings.HasSuffix(val, "h"), strings.HasSuffix(val, "m"), strings.HasSuffix(val, "s"):
		return (time.Duration(v) * time.Millisecond).Round(time.Second).String()
	}
	for g, n := range grades {
		if n == v && strings.EqualFold(val, strings.Trim(val, "0123456789")) {
			return g
		}
	}
	if v == math.Trunc(v) {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}
