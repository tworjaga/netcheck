package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAssetName(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"windows", "amd64"}: "netcheck-windows-amd64.exe",
		{"darwin", "arm64"}:  "netcheck-macos-arm64",
		{"linux", "arm64"}:   "netcheck-linux-arm64",
	} {
		if got := AssetName(in[0], in[1]); got != want {
			t.Errorf("%v: %s", in, got)
		}
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		latest, current string
		want            bool
	}{
		{"v0.10.0", "0.9.0", true}, {"v0.9.0", "0.9.0", false}, {"v0.9.0", "0.10.0", false},
		{"v1.0.0", "0.99.9", true}, {"v0.9.1", "dev", true}, {"nonsense", "0.9.0", false},
		{"v0.10.0-rc1", "0.9.0", true},
	} {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.latest, c.current, got)
		}
	}
}

func TestVerify(t *testing.T) {
	data := []byte("binary")
	sum := sha256.Sum256(data)
	sums := []byte(hex.EncodeToString(sum[:]) + "  netcheck-linux-amd64\n" + strings.Repeat("0", 64) + "  netcheck-linux-arm64\n")
	if err := Verify(sums, "netcheck-linux-amd64", data); err != nil {
		t.Error(err)
	}
	if err := Verify(sums, "netcheck-linux-arm64", data); err == nil || !strings.Contains(err.Error(), "doesn't match") {
		t.Errorf("a wrong hash must stop it: %v", err)
	}
	if err := Verify(sums, "netcheck-windows-amd64.exe", data); err == nil {
		t.Error("an unlisted file must stop it")
	}
}

// fakeGitHub serves a release with one binary and its SHA256SUMS.
func fakeGitHub(t *testing.T, wantAuth string) *httptest.Server {
	t.Helper()
	bin := []byte("new netcheck")
	sum := sha256.Sum256(bin)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != wantAuth {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/latest":
			fmt.Fprintf(w, `{"tag_name":"v0.10.0","html_url":"%[1]s/page","assets":[
				{"name":"netcheck-linux-amd64","browser_download_url":"%[1]s/dl/bin","url":"%[1]s/api/bin"},
				{"name":"SHA256SUMS","browser_download_url":"%[1]s/dl/sums","url":"%[1]s/api/sums"}]}`, srv.URL)
		case "/dl/bin", "/api/bin":
			if r.URL.Path == "/api/bin" && r.Header.Get("Accept") != "application/octet-stream" {
				http.Error(w, "json", 415)
				return
			}
			w.Write(bin)
		case "/dl/sums", "/api/sums":
			fmt.Fprintf(w, "%s  netcheck-linux-amd64\n", hex.EncodeToString(sum[:]))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := API
	API = srv.URL + "/latest"
	t.Cleanup(func() { API = old })
	return srv
}

func TestLatestAndFetch(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	fakeGitHub(t, "")
	ctx := context.Background()
	r, err := Latest(ctx)
	if err != nil || r.Version() != "0.10.0" {
		t.Fatalf("%+v %v", r, err)
	}
	bin, err := r.Fetch(ctx, "netcheck-linux-amd64")
	sums, err2 := r.Fetch(ctx, "SHA256SUMS")
	if err != nil || err2 != nil || Verify(sums, "netcheck-linux-amd64", bin) != nil {
		t.Errorf("%q %v %v", bin, err, err2)
	}
	if _, err := r.Fetch(ctx, "netcheck-plan9-amd64"); err == nil {
		t.Error("a missing file is an error")
	}
}

func TestPrivateRepoNeedsAToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	fakeGitHub(t, "Bearer secret")
	if _, err := Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Errorf("without a token: %v", err)
	}
	t.Setenv("GITHUB_TOKEN", "secret")
	r, err := Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// With a token, files come through the API (as private repos need).
	if bin, err := r.Fetch(context.Background(), "netcheck-linux-amd64"); err != nil || string(bin) != "new netcheck" {
		t.Errorf("%q %v", bin, err)
	}
}
