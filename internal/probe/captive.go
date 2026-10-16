package probe

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CaptiveCheck is one of the operating systems' own "am I online?" URLs:
// plain HTTP, with a known answer. A captive portal (hotel, café, airport)
// intercepts it and answers with a redirect or its own login page.
type CaptiveCheck struct {
	Name   string // whose check it is, for display
	URL    string
	Status int    // expected status code
	Body   string // expected body substring ("" = empty body expected)
}

var captiveChecks = []CaptiveCheck{
	{Name: "Google", URL: "http://connectivitycheck.gstatic.com/generate_204", Status: 204},
	{Name: "Apple", URL: "http://captive.apple.com/hotspot-detect.html", Status: 200, Body: "Success"},
	{Name: "Microsoft", URL: "http://www.msftconnecttest.com/connecttest.txt", Status: 200, Body: "Microsoft Connect Test"},
}

// CaptiveProbe is the outcome of one check URL.
type CaptiveProbe struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Status   int    `json:"status,omitempty"`
	Intact   bool   `json:"intact"`             // the expected answer came back
	Redirect string `json:"redirect,omitempty"` // where a portal sent us
	Error    string `json:"error,omitempty"`    // no answer at all
}

// CaptiveResult summarizes all check URLs.
type CaptiveResult struct {
	Probes []CaptiveProbe `json:"probes"`
}

// noRedirect is a client that reports redirects instead of following them.
func noRedirect() *http.Client {
	return &http.Client{
		Timeout:   6 * time.Second,
		Transport: HTTPClient.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func checkCaptive(ctx context.Context, c CaptiveCheck) CaptiveProbe {
	p := CaptiveProbe{Name: c.Name, URL: c.URL}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := noRedirect().Do(req)
	if err != nil {
		p.Error = shortErr(err)
		return p
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	p.Status = resp.StatusCode
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc, err := resp.Location(); err == nil {
			p.Redirect = loc.Host
		} else {
			p.Redirect = resp.Header.Get("Location")
		}
		return p
	}
	switch {
	case resp.StatusCode != c.Status:
	case c.Body == "":
		p.Intact = len(strings.TrimSpace(string(body))) == 0
	default:
		p.Intact = strings.Contains(string(body), c.Body)
	}
	if !p.Intact {
		p.Redirect = metaRefresh(string(body))
	}
	return p
}

// metaRefresh finds a portal's <meta http-equiv="refresh" content="0;url=…">
// or a JavaScript-free link host, for naming the portal.
func metaRefresh(body string) string {
	low := strings.ToLower(body)
	i := strings.Index(low, "url=")
	if i < 0 {
		return ""
	}
	rest := body[i+4:]
	end := strings.IndexAny(rest, "\"'> ")
	if end > 0 {
		rest = rest[:end]
	}
	if u, err := url.Parse(strings.TrimSpace(rest)); err == nil && u.Host != "" {
		return u.Host
	}
	return ""
}

// CheckCaptive asks every check URL at once.
func CheckCaptive(ctx context.Context) CaptiveResult {
	res := CaptiveResult{Probes: make([]CaptiveProbe, len(captiveChecks))}
	done := make(chan struct{}, len(captiveChecks))
	for i, c := range captiveChecks {
		go func() {
			res.Probes[i] = checkCaptive(ctx, c)
			done <- struct{}{}
		}()
	}
	for range captiveChecks {
		<-done
	}
	return res
}
