package cli

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"github.com/tworjaga/netcheck/internal/agent"
	"github.com/tworjaga/netcheck/internal/ui"
	"github.com/tworjaga/netcheck/internal/update"
)

// selfPath is the running binary (a test seam).
var selfPath = func() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

// agentRunning reports whether the agent service runs (a test seam).
var agentRunning = func() bool {
	s := agent.ServiceState(os.Geteuid() == 0)
	return s.Installed && s.Running
}

type updateResult struct {
	Current string `json:"current"`
	Latest  string `json:"latest"`
	Newer   bool   `json:"newer"`
	Updated bool   `json:"updated"`
	Path    string `json:"path,omitempty"`
	Error   string `json:"error,omitempty"`
}

func cmdUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	check := fs.Bool("check", false, "only say whether a newer release is out")
	asJSON := fs.Bool("json", false, "machine-readable output")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	res := updateResult{Current: version}
	done := func(st ui.Status, msg string, notes ...string) int {
		ui.Verdict(st, msg, notes...)
		ui.Println("")
		if *asJSON {
			printJSON(res)
		}
		if st == ui.Bad {
			return 1
		}
		return 0
	}
	ui.Title("update")
	t := ui.Begin("Checking")
	t.Progress("GitHub for the latest release…")
	rel, err := update.Latest(ctx)
	t.Clear()
	if err != nil {
		res.Error = err.Error()
		return done(ui.Bad, "Couldn't check for a newer version: "+err.Error()+".")
	}
	res.Latest = rel.Version()
	res.Newer = update.Newer(rel.Tag, version)
	if !res.Newer {
		return done(ui.OK, "netcheck "+version+" is the latest version.")
	}
	if *check {
		return done(ui.Warn, "netcheck "+rel.Version()+" is out; this is "+version+".", "netcheck update installs it. What's new: "+rel.Page)
	}

	self, err := selfPath()
	if err != nil {
		res.Error = err.Error()
		return done(ui.Bad, "Couldn't find this netcheck: "+err.Error()+".")
	}
	name := update.AssetName(runtime.GOOS, runtime.GOARCH)
	t = ui.Begin("Downloading")
	t.Progress(name + " " + rel.Tag + "…")
	bin, err := rel.Fetch(ctx, name)
	var sums []byte
	if err == nil {
		sums, err = rel.Fetch(ctx, "SHA256SUMS")
	}
	if err == nil {
		err = update.Verify(sums, name, bin)
	}
	if err != nil {
		t.Clear()
		res.Error = err.Error()
		return done(ui.Bad, "Couldn't update: "+err.Error()+".")
	}
	t.Progress("replacing " + self + "…")
	err = replaceSelf(self, bin)
	t.Clear()
	if err != nil {
		res.Error = err.Error()
		return done(ui.Bad, "Downloaded and checked, but couldn't replace "+self+": "+err.Error()+".")
	}
	res.Updated, res.Path = true, self
	notes := []string{"The download matched the release's SHA256SUMS. What's new: " + rel.Page}
	if agentRunning() && isInstalledCopy(self) {
		notes = append(notes, "The agent service still runs the old version until it restarts; netcheck agent install restarts it.")
	}
	return done(ui.OK, "Updated netcheck from "+version+" to "+rel.Version()+".", notes...)
}

// isInstalledCopy reports whether path is the copy netcheck install put
// on the PATH, which is the one the agent service runs.
func isInstalledCopy(path string) bool {
	dir, err := installDir()
	if err != nil {
		return false
	}
	a, err1 := os.Stat(path)
	b, err2 := os.Stat(filepath.Join(dir, binaryName()))
	return err1 == nil && err2 == nil && os.SameFile(a, b)
}

// replaceSelf writes the new binary beside the running one, then swaps it
// in the way install does (a running copy is moved aside first).
func replaceSelf(self string, bin []byte) error {
	f, err := os.CreateTemp(filepath.Dir(self), ".netcheck-update-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(bin); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return copyBinary(tmp, self)
}
