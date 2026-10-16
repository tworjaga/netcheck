package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPClient is shared by every lookup that talks to a web service. Each
// call also gets its own context timeout, so nothing can hang.
var HTTPClient = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 6 * time.Second,
		MaxIdleConnsPerHost:   8,
	},
}

const userAgent = "netcheck (+https://github.com/tworjaga/netcheck)"

// httpGet fetches url and returns at most max bytes of the body.
func httpGet(ctx context.Context, url string, max int64) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.Header, fmt.Errorf("http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max))
	return b, resp.Header, err
}

// limitBody caps how much of a response body we'll read.
func limitBody(r *http.Response) io.Reader { return io.LimitReader(r.Body, 64<<10) }
