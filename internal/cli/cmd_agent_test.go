package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tworjaga/netcheck/internal/uptime"
)

func TestSplitFrom(t *testing.T) {
	cases := map[string][2]string{
		"example.com --from vps MX": {"vps", "example.com MX"},
		"--from=vps example.com":    {"vps", "example.com"},
		"example.com -from vps":     {"vps", "example.com"},
		"example.com MX":            {"", "example.com MX"},
		"example.com --from":        {"", "example.com"},
	}
	for in, want := range cases {
		from, rest := splitFrom(strings.Fields(in))
		if from != want[0] || strings.Join(rest, " ") != want[1] {
			t.Errorf("%q: %q %q", in, from, rest)
		}
	}
}

func TestLoadWatchFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "servers.txt")
	os.WriteFile(p, []byte("# shop\nhttps://shop.test name=Shop\ntcp://db.test:5432\nhttps://shop.test\nalert desktop\nalert webhook https://ntfy.sh/x\n"), 0o600)
	targets, chans, err := loadWatchFile(p)
	if err != nil || len(targets) != 2 || targets[0].Name != "Shop" || len(chans) != 2 {
		t.Fatalf("%+v %d %v", targets, len(chans), err)
	}
	os.WriteFile(p, []byte("alert desktop\n"), 0o600)
	if _, _, err := loadWatchFile(p); err == nil {
		t.Error("alerts alone watch nothing")
	}
	if _, _, err := loadWatchFile(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("a missing file is an error")
	}
}

func TestAgentWatchKeepsRecentEvents(t *testing.T) {
	w := &agentWatch{}
	for i := 0; i < 25; i++ {
		w.add([]uptime.Event{{Text: strings.Repeat("x", i)}})
	}
	if len(w.events) != 20 || len(w.events[19].Text) != 24 {
		t.Errorf("%d events", len(w.events))
	}
}
