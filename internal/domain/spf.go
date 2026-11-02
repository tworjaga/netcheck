package domain

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// SPFCount is how many DNS lookups evaluating a domain's SPF record takes.
// Receivers stop at 10 (RFC 7208 4.6.4) and treat the record as broken,
// and at 2 lookups that find nothing ("void" lookups).
type SPFCount struct {
	Lookups  int            `json:"lookups"`
	Void     int            `json:"void_lookups"`
	Includes map[string]int `json:"includes,omitempty"` // top-level include or redirect → lookups under it, itself included
	Missing  []string       `json:"missing,omitempty"`  // included domains without an SPF record
	Multiple []string       `json:"multiple,omitempty"` // included domains with more than one
	Loop     bool           `json:"loop,omitempty"`
}

// countSPF walks the record from domain down through every include and
// redirect.
func countSPF(ctx context.Context, domain string) SPFCount {
	c := SPFCount{Includes: map[string]int{}}
	seen := map[string]bool{}
	var walk func(d string, depth int, top string) int
	walk = func(d string, depth int, top string) int {
		key := strings.ToLower(strings.TrimSuffix(d, "."))
		if seen[key] || depth > 10 {
			c.Loop = true
			return 0
		}
		seen[key] = true
		defer delete(seen, key)
		recs, err := txts(ctx, d, "v=spf1")
		if err != nil {
			return 0
		}
		switch {
		case len(recs) == 0:
			if depth > 0 {
				c.Void++
				c.Missing = append(c.Missing, key)
			}
			return 0
		case len(recs) > 1 && depth > 0:
			c.Multiple = append(c.Multiple, key)
		}
		n := 0
		for _, term := range strings.Fields(recs[0])[1:] {
			t := strings.ToLower(strings.TrimLeft(term, "+-~?"))
			mech, arg, _ := strings.Cut(t, ":")
			if strings.HasPrefix(t, "redirect=") {
				mech, arg = "redirect", strings.TrimPrefix(t, "redirect=")
			}
			mech, _, _ = strings.Cut(mech, "/") // "a/24", "mx/24"
			switch mech {
			case "include", "redirect":
				n++
				label := top
				if depth == 0 {
					label = mech + ":" + arg
				}
				if strings.Contains(arg, "%") { // a macro: can't follow it
					continue
				}
				sub := walk(arg, depth+1, label)
				n += sub
				if depth == 0 {
					c.Includes[label] = 1 + sub
				}
			case "a", "mx", "ptr", "exists":
				n++
			}
		}
		return n
	}
	c.Lookups = walk(domain, 0, "")
	sort.Strings(c.Missing)
	sort.Strings(c.Multiple)
	return c
}

// spfCountChecks turns the count into findings.
func spfCountChecks(c SPFCount) []Check {
	var cs []Check
	var parts []string
	for k, v := range c.Includes {
		parts = append(parts, fmt.Sprintf("%s %d", k, v))
	}
	sort.Strings(parts)
	detail := strings.Join(parts, ", ")
	switch {
	case c.Lookups > 10:
		cs = append(cs, Check{AreaSPF, Bad, fmt.Sprintf("SPF needs %d DNS lookups (the limit is 10)", c.Lookups), detail,
			"Receivers treat the record as broken (permerror), so SPF fails for all your mail. Drop includes you no longer use, or replace some with ip4:/ip6: ranges."})
	case c.Lookups >= 9:
		cs = append(cs, Check{AreaSPF, Warn, fmt.Sprintf("SPF needs %d of 10 DNS lookups", c.Lookups), detail,
			"One more include breaks SPF for all your mail; trim the record before adding a sender."})
	default:
		cs = append(cs, Check{AreaSPF, OK, fmt.Sprintf("SPF needs %d of 10 DNS lookups", c.Lookups), detail, ""})
	}
	if len(c.Missing) > 0 {
		st := Warn
		if c.Void > 2 {
			st = Bad
		}
		cs = append(cs, Check{AreaSPF, st, "SPF includes a domain without SPF", strings.Join(c.Missing, ", "),
			"Remove the include, or fix the name: an include that finds nothing fails SPF for everything after it."})
	}
	if len(c.Multiple) > 0 {
		cs = append(cs, Check{AreaSPF, Bad, "An included domain has two SPF records", strings.Join(c.Multiple, ", "),
			"Receivers treat that as an error; the owner of that domain has to merge them, or drop the include."})
	}
	if c.Loop {
		cs = append(cs, Check{AreaSPF, Bad, "SPF includes loop back on themselves", "", "Remove the include that points back at a domain already in the chain."})
	}
	return cs
}
