package adv

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/tworjaga/netcheck/internal/ui"
)

// Flags are the options every Advanced tool takes, registered the same way
// so they read the same everywhere.
type Flags struct {
	JSON       bool
	Raw        bool
	FailOn     string
	Watch      time.Duration
	File       string
	Authorized bool
}

// Register adds the common flags to a tool's flag set.
func Register(fs *flag.FlagSet) *Flags {
	f := &Flags{}
	fs.BoolVar(&f.JSON, "json", false, "machine-readable output")
	fs.BoolVar(&f.Raw, "raw", false, "measurements only, without verdicts")
	fs.StringVar(&f.FailOn, "fail-on", "", "exit 1 when a rule breaks, e.g. 14d or loss>1%,rtt>200ms")
	fs.DurationVar(&f.Watch, "watch", 0, "rerun as a live view at this interval, e.g. --watch 5s")
	fs.StringVar(&f.File, "f", "", "read targets from a file, one per line (# comments)")
	fs.BoolVar(&f.Authorized, "authorized", false, "you're allowed to test targets outside your own networks")
	return f
}

// Rules parses --fail-on (nil when it's not set).
func (f *Flags) Rules() ([]Rule, error) {
	if f.FailOn == "" {
		return nil, nil
	}
	return ParseRules(f.FailOn)
}

// ExitCode is 1 when the verdict is a hard failure or a --fail-on rule
// broke, else 0.
func ExitCode(verdict string, broken []string) int {
	if verdict == "bad" || len(broken) > 0 {
		return 1
	}
	return 0
}

// MinWatch keeps --watch from hammering a target.
const MinWatch = time.Second

// Watch reruns check every interval until ctx ends. On a terminal each
// round replaces the last in place under a status line; piped, each round
// prints in full after a timestamp.
func Watch(ctx context.Context, every time.Duration, check func(context.Context) []string) {
	every = max(every, MinWatch)
	var blk ui.Block
	live := ui.Interactive()
	for round := 1; ctx.Err() == nil; round++ {
		start := time.Now()
		lines := check(ctx)
		if ctx.Err() != nil {
			break
		}
		head := fmt.Sprintf("%s · round %d · every %s · Ctrl-C to stop", start.Format("15:04:05"), round, every)
		if live {
			blk.Update(append([]string{"  " + ui.Dim(head), ""}, lines...))
		} else {
			fmt.Println("# " + head)
			for _, l := range lines {
				fmt.Println(l)
			}
			fmt.Println()
		}
		t := time.NewTimer(time.Until(start.Add(every)))
		select {
		case <-ctx.Done():
		case <-t.C:
		}
		t.Stop()
	}
	if live {
		blk.End(nil)
	}
}
