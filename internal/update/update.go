// Package update finds netcheck's latest release on GitHub, downloads the
// binary for this system and checks it against the release's SHA256SUMS.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Repo is where releases are published.
const Repo = "tworjaga/netcheck"

// API is the latest-release endpoint (a test seam).
var API = "https://api.github.com/repos/" + Repo + "/releases/latest"

var client = &http.Client{Timeout: 3 * time.Minute}

// Release is the part of GitHub's answer netcheck uses.
type Release struct {
	Tag    string  `json:"tag_name"`
	Page   string  `json:"html_url"`
	Assets []Asset `json:"assets"`
}

// Asset is one file of a release.
type Asset struct {
	Name     string `json:"name"`
	Download string `json:"browser_download_url"`
	API      string `json:"url"`
	Size     int64  `json:"size"`
}

// Version is the tag without its "v".
func (r Release) Version() string { return strings.TrimPrefix(r.Tag, "v") }

// AssetName is the release file for an OS and architecture, as the
// release workflow names them.
func AssetName(goos, goarch string) string {
	name, ext := goos, ""
	switch goos {
	case "darwin":
		name = "macos"
	case "windows":
		ext = ".exe"
	}
	return "netcheck-" + name + "-" + goarch + ext
}

// request adds GitHub's headers; GITHUB_TOKEN (or GH_TOKEN) is used when
// set, which a private repository needs.
func request(ctx context.Context, url, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "netcheck-update")
	if t := token(); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	return client.Do(req)
}

func token() string {
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GH_TOKEN")
}

// Latest asks GitHub for the newest release.
func Latest(ctx context.Context) (Release, error) {
	var r Release
	res, err := request(ctx, API, "application/vnd.github+json")
	if err != nil {
		return r, fmt.Errorf("can't reach GitHub: %v", err)
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusNotFound && token() == "":
		return r, fmt.Errorf("GitHub has no release for %s (a private repository needs GITHUB_TOKEN)", Repo)
	case res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusTooManyRequests:
		return r, fmt.Errorf("GitHub refused (%s); its limit for anonymous requests resets within an hour", res.Status)
	case res.StatusCode != http.StatusOK:
		return r, fmt.Errorf("GitHub answered %s", res.Status)
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&r); err != nil || r.Tag == "" {
		return r, fmt.Errorf("GitHub's answer didn't name a release")
	}
	return r, nil
}

// Fetch downloads one file of the release.
func (r Release) Fetch(ctx context.Context, name string) ([]byte, error) {
	for _, a := range r.Assets {
		if a.Name != name {
			continue
		}
		url, accept := a.Download, "application/octet-stream"
		if token() != "" && a.API != "" {
			url = a.API // the API serves files of private repositories too
		}
		res, err := request(ctx, url, accept)
		if err != nil {
			return nil, fmt.Errorf("downloading %s: %v", name, err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("downloading %s: %s", name, res.Status)
		}
		return io.ReadAll(io.LimitReader(res.Body, 200<<20))
	}
	return nil, fmt.Errorf("release %s has no %s", r.Tag, name)
}

// Verify checks data against its line in a SHA256SUMS file.
func Verify(sums []byte, name string, data []byte) error {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 || strings.TrimPrefix(f[1], "*") != name {
			continue
		}
		got := sha256.Sum256(data)
		if !strings.EqualFold(f[0], hex.EncodeToString(got[:])) {
			return fmt.Errorf("%s doesn't match SHA256SUMS; not installed", name)
		}
		return nil
	}
	return fmt.Errorf("SHA256SUMS doesn't list %s", name)
}

// Newer reports whether latest is a later version than current. A build
// without a version ("dev") counts as older than any release.
func Newer(latest, current string) bool {
	l, okL := parse(latest)
	c, okC := parse(current)
	if !okL {
		return false
	}
	if !okC {
		return true
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func parse(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v, _, _ = strings.Cut(v, "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
