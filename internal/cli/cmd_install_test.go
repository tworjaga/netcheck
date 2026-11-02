package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPathListHelpers(t *testing.T) {
	sep := string(os.PathListSeparator)
	a, b, nc := filepath.Join("x", "a"), filepath.Join("x", "b"), filepath.Join("x", "netcheck")
	list := a + sep + b
	if pathHas(list, nc) || !pathHas(list, b) {
		t.Fatal("pathHas")
	}
	added := pathAdd(list, nc)
	if added != list+sep+nc || pathAdd(added, nc) != added {
		t.Errorf("pathAdd adds once: %q", added)
	}
	if pathAdd("", nc) != nc {
		t.Errorf("pathAdd to an empty PATH")
	}
	if got := pathRemove(added+sep+nc, nc); got != list {
		t.Errorf("pathRemove drops every copy: %q", got)
	}
	if pathHas(list, nc+string(os.PathSeparator)) {
		t.Errorf("a trailing separator doesn't make a match")
	}
}

// fakeUserPath swaps the user PATH store for a variable.
func fakeUserPath(t *testing.T, start string) *string {
	t.Helper()
	store := start
	oldGet, oldSet := userPath, setUserPath
	userPath = func() (string, error) { return store, nil }
	setUserPath = func(v string) error { store = v; return nil }
	t.Cleanup(func() { userPath, setUserPath = oldGet, oldSet })
	return &store
}

func TestInstallAndUninstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Programs", "netcheck")
	t.Setenv("NETCHECK_INSTALL_DIR", dir)
	other := filepath.Join(t.TempDir(), "tools")
	store := fakeUserPath(t, other)

	if code := cmdInstall([]string{"--json"}); code != 0 {
		t.Fatalf("install exit %d", code)
	}
	dest := filepath.Join(dir, binaryName())
	if fi, err := os.Stat(dest); err != nil || fi.Size() == 0 {
		t.Fatalf("binary not copied: %v", err)
	}
	if !pathHas(*store, dir) || !pathHas(*store, other) {
		t.Fatalf("PATH should keep the old entry and add the new one: %q", *store)
	}
	// Installing again neither duplicates the PATH entry nor fails.
	if code := cmdInstall([]string{"--json"}); code != 0 || strings.Count(*store, dir) != 1 {
		t.Fatalf("reinstall: exit %d, PATH %q", code, *store)
	}

	if code := cmdUninstall([]string{"--json"}); code != 0 {
		t.Fatalf("uninstall exit %d", code)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Errorf("binary still there")
	}
	if pathHas(*store, dir) || !pathHas(*store, other) {
		t.Errorf("uninstall removes only its own PATH entry: %q", *store)
	}
}

func TestInstallAsksFirst(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "netcheck")
	t.Setenv("NETCHECK_INSTALL_DIR", dir)
	store := fakeUserPath(t, "")
	// Not a terminal (a script, cron, CI): without --yes nothing may change.
	oldTTY := stdinIsTTY
	stdinIsTTY = func() bool { return false }
	defer func() { stdinIsTTY = oldTTY }()
	if code := cmdInstall(nil); code != 2 {
		t.Fatalf("want exit 2 (needs --yes), got %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, binaryName())); err == nil || *store != "" {
		t.Fatalf("nothing should change without consent")
	}
	// Saying no at the prompt changes nothing either.
	old := confirm
	confirm = func(string) bool { return false }
	defer func() { confirm = old }()
	stdinIsTTY = func() bool { return true }
	if code := cmdInstall(nil); code != 0 {
		t.Fatalf("declined install: exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, binaryName())); err == nil || *store != "" {
		t.Fatalf("declining must not change anything")
	}
}

func TestAsideNameSkipsACopyStillInUse(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "netcheck.exe")
	if got := asideName(dest); got != dest+".old" {
		t.Errorf("first: %s", got)
	}
	// A directory can't be removed by os.Remove when it has files: it
	// stands in for an old copy that is still running.
	os.MkdirAll(filepath.Join(dest+".old", "busy"), 0o755)
	os.WriteFile(dest+".old3", []byte("x"), 0o644)
	if got := asideName(dest); got != dest+".old2" {
		t.Errorf("busy .old: %s", got)
	}
	if _, err := os.Stat(dest + ".old3"); !os.IsNotExist(err) {
		t.Error("old copies that can go are removed")
	}
}
