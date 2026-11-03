package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func get(t *testing.T, s *server, path string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil) // RemoteAddr is 192.0.2.1:1234
	s.ServeHTTP(rec, req)
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	return rec.Code, v
}

func TestChecksOnlyTheCallersOwnAddress(t *testing.T) {
	s := newServer(true)
	var dialed string
	s.dial = func(_ context.Context, addr string) bool { dialed = addr; return true }
	code, v := get(t, s, "/check?port=8080&host=10.0.0.5") // a "host" parameter must be ignored
	if code != 200 || v["open"] != true || dialed != net.JoinHostPort("192.0.2.1", "8080") {
		t.Fatalf("code=%d v=%v dialed=%q", code, v, dialed)
	}
}

func TestRejectsBadPortsAndPrivateCallers(t *testing.T) {
	s := newServer(true)
	s.dial = func(_ context.Context, _ string) bool { return false }
	for _, p := range []string{"/check?port=0", "/check?port=70000", "/check?port=abc", "/check"} {
		if code, _ := get(t, s, p); code != 400 {
			t.Errorf("%s: code %d, want 400", p, code)
		}
	}
	strict := newServer(false) // production rules: only public callers
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/check?port=80", nil)
	req.RemoteAddr = "192.168.1.9:5000"
	strict.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Errorf("a private caller must be refused, got %d", rec.Code)
	}
}

func TestRateLimit(t *testing.T) {
	s := newServer(true)
	s.dial = func(_ context.Context, _ string) bool { return false }
	last := 0
	for i := 0; i < 11; i++ {
		last, _ = get(t, s, "/check?port=80")
	}
	if last != 429 {
		t.Fatalf("11th request in a minute should be limited, got %d", last)
	}
}
