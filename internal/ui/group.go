package ui

import (
	"sync"
	"time"
)

// Group is a set of rows that work in parallel: each shows a spinner until
// it resolves into its result line, in place. Rows can be added while the
// group runs. Off a terminal nothing animates and the final lines print,
// in order, when the group ends.
type Group struct {
	mu     sync.Mutex
	rows   []groupRow
	block  Block
	live   bool
	frame  int
	stop   chan struct{}
	done   chan struct{}
	silent bool
}

type groupRow struct {
	label, text, final string
	resolved           bool
}

// NewSilentGroup is a Group that never draws, for work whose rows aren't
// shown (a report measuring behind a single spinner).
func NewSilentGroup() *Group {
	g := &Group{stop: make(chan struct{}), done: make(chan struct{}), silent: true}
	close(g.done)
	return g
}

// NewGroup starts a group with the given row labels.
func NewGroup(labels ...string) *Group {
	g := &Group{stop: make(chan struct{}), done: make(chan struct{})}
	for _, l := range labels {
		g.rows = append(g.rows, groupRow{label: l})
	}
	if ttyOut && !quiet {
		g.live = true
		go g.loop()
	} else {
		close(g.done)
	}
	return g
}

// Add appends a pending row and returns its index.
func (g *Group) Add(label string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rows = append(g.rows, groupRow{label: label})
	return len(g.rows) - 1
}

// Progress sets the text next to row i's spinner.
func (g *Group) Progress(i int, s string) {
	g.mu.Lock()
	g.rows[i].text = s
	g.mu.Unlock()
}

// Finish resolves row i into its final line ("" hides the row).
func (g *Group) Finish(i int, line string) {
	g.mu.Lock()
	g.rows[i].final, g.rows[i].resolved = line, true
	g.mu.Unlock()
}

func (g *Group) lines() []string {
	frames := spinnerFrames()
	var out []string
	for _, r := range g.rows {
		switch {
		case r.resolved && r.final != "":
			out = append(out, r.final)
		case r.resolved:
		default:
			out = append(out, "  "+pad(r.label, labelW)+Accent(frames[g.frame%len(frames)])+"  "+r.text)
		}
	}
	return out
}

func (g *Group) loop() {
	defer close(g.done)
	tick := time.NewTicker(80 * time.Millisecond)
	defer tick.Stop()
	for {
		g.mu.Lock()
		g.frame++
		g.block.Update(g.lines())
		g.mu.Unlock()
		select {
		case <-g.stop:
			return
		case <-tick.C:
		}
	}
}

// End stops the spinners and leaves the final lines on screen. Rows that
// never resolved (Ctrl-C) are dropped.
func (g *Group) End() {
	if g.live {
		close(g.stop)
	}
	<-g.done
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for _, r := range g.rows {
		if r.resolved && r.final != "" {
			out = append(out, r.final)
		}
	}
	if !g.silent {
		g.block.End(out)
	}
}
