package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestScanPortsFindsOnlyOpen(t *testing.T) {
	port, stop := freeTCP(t)
	defer stop()
	closed, stopClosed := freeTCP(t)
	stopClosed()
	got := ScanPorts(context.Background(), "127.0.0.1", []PortInfo{{closed, "nothing"}, {port, "fake"}}, 500*time.Millisecond)
	if len(got) != 1 || got[0].Port != port || got[0].Service != "fake" {
		t.Fatalf("got %+v", got)
	}
}

func TestScanPortsStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := ScanPorts(ctx, "127.0.0.1", CommonPorts, time.Second); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestIsLocalAddr(t *testing.T) {
	for s, want := range map[string]bool{"192.168.1.5": true, "10.0.0.1": true, "172.16.4.4": true, "127.0.0.1": true, "169.254.1.1": true, "8.8.8.8": false, "100.64.0.1": false} {
		if got := IsLocalAddr(net.ParseIP(s)); got != want {
			t.Errorf("IsLocalAddr(%s) = %v, want %v", s, got, want)
		}
	}
}

func helperServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/check" || r.URL.Query().Get("port") == "" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExternalCheck(t *testing.T) {
	open := helperServer(t, `{"ip":"203.0.113.7","port":25565,"open":true}`, 200)
	if r := ExternalCheck(context.Background(), open.URL, 25565); !r.Open || r.IP != "203.0.113.7" || r.Error != "" {
		t.Fatalf("open: %+v", r)
	}
	closed := helperServer(t, `{"ip":"203.0.113.7","port":25565,"open":false}`, 200)
	if r := ExternalCheck(context.Background(), closed.URL+"/", 25565); r.Open || r.Error != "" {
		t.Fatalf("closed (trailing slash allowed): %+v", r)
	}
}

func TestExternalCheckFailures(t *testing.T) {
	cases := []struct {
		name, helper, want string
	}{
		{"rate limited", helperServer(t, "slow down", 429).URL, "rate limiting"},
		{"garbage", helperServer(t, "<html>", 200).URL, "wasn't understood"},
		{"helper error", helperServer(t, `{"error":"port not allowed"}`, 200).URL, "port not allowed"},
		{"helper refuses with a reason", helperServer(t, `{"error":"your address isn't a public internet address"}`, 400).URL, "isn't a public internet address"},
		{"helper fails without a reason", helperServer(t, `{}`, 500).URL, "HTTP 500"},
		{"unreachable", "http://127.0.0.1:1", "couldn't reach"},
		{"bad url", "ftp://nope", "valid http"},
		{"empty", "", "valid http"},
	}
	for _, c := range cases {
		r := ExternalCheck(context.Background(), c.helper, 80)
		if r.Open || !strings.Contains(r.Error, c.want) {
			t.Errorf("%s: got %+v", c.name, r)
		}
	}
}
