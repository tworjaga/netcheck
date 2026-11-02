package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tworjaga/netcheck/internal/update"
)

func fakeRelease(t *testing.T, tag string, bin []byte, sumOf []byte) {
	t.Helper()
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	name := update.AssetName(runtime.GOOS, runtime.GOARCH)
	sum := sha256.Sum256(sumOf)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			fmt.Fprintf(w, `{"tag_name":%q,"html_url":"%[2]s/page","assets":[{"name":%q,"browser_download_url":"%[2]s/bin"},{"name":"SHA256SUMS","browser_download_url":"%[2]s/sums"}]}`, tag, srv.URL, name)
		case "/bin":
			w.Write(bin)
		case "/sums":
			fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), name)
		}
	}))
	t.Cleanup(srv.Close)
	old := update.API
	update.API = srv.URL + "/latest"
	t.Cleanup(func() { update.API = old })
}

func fakeSelf(t *testing.T) string {
	t.Helper()
	self := filepath.Join(t.TempDir(), "netcheck")
	os.WriteFile(self, []byte("old netcheck"), 0o755)
	oldSelf, oldAgent, oldVersion := selfPath, agentRunning, version
	selfPath = func() (string, error) { return self, nil }
	agentRunning = func() bool { return false }
	version = "0.9.0"
	t.Cleanup(func() { selfPath, agentRunning, version = oldSelf, oldAgent, oldVersion })
	return self
}

func TestUpdateReplacesTheBinary(t *testing.T) {
	self := fakeSelf(t)
	fakeRelease(t, "v0.10.0", []byte("new netcheck"), []byte("new netcheck"))
	if code := cmdUpdate([]string{"--json"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if b, _ := os.ReadFile(self); string(b) != "new netcheck" {
		t.Errorf("binary is %q", b)
	}
}

func TestUpdateRefusesABadDownload(t *testing.T) {
	self := fakeSelf(t)
	fakeRelease(t, "v0.10.0", []byte("tampered"), []byte("new netcheck"))
	if code := cmdUpdate([]string{"--json"}); code != 1 {
		t.Errorf("exit %d", code)
	}
	if b, _ := os.ReadFile(self); string(b) != "old netcheck" {
		t.Errorf("a file that fails the check must not be installed: %q", b)
	}
}

func TestUpdateCheckAndLatest(t *testing.T) {
	self := fakeSelf(t)
	fakeRelease(t, "v0.10.0", []byte("new netcheck"), []byte("new netcheck"))
	if code := cmdUpdate([]string{"--check", "--json"}); code != 0 {
		t.Errorf("--check exit %d", code)
	}
	if b, _ := os.ReadFile(self); string(b) != "old netcheck" {
		t.Error("--check changes nothing")
	}
	fakeRelease(t, "v0.9.0", []byte("same"), []byte("same"))
	if code := cmdUpdate([]string{"--json"}); code != 0 {
		t.Errorf("already latest: exit %d", code)
	}
	if b, _ := os.ReadFile(self); string(b) != "old netcheck" {
		t.Error("nothing to do when it's the latest")
	}
}
