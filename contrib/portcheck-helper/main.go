// portcheck-helper is the reference server for `netcheck ports -x PORT`.
//
// It answers GET /check?port=N by connecting back to the address the request
// came from, and replies {"ip":"...","port":N,"open":true|false}. It never
// takes a target from the caller, so it can only test the caller's own
// connection. Run it on a machine outside your home network, for example a
// small VPS:
//
//	go run ./contrib/portcheck-helper -addr :8080
//
// and point netcheck at it with --helper http://your-server:8080 or the
// NETCHECK_PORT_HELPER environment variable. Put it behind TLS if you expose
// it beyond a trusted circle; it sees the caller's address and the port.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type server struct {
	dial         func(ctx context.Context, addr string) bool
	allowPrivate bool
	limit        int // requests per minute per caller
	mu           sync.Mutex
	hits         map[string][]time.Time
}

func (s *server) allow(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	keep := s.hits[ip][:0]
	for _, t := range s.hits[ip] {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= s.limit {
		s.hits[ip] = keep
		return false
	}
	s.hits[ip] = append(keep, now)
	return true
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/check" {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("netcheck port helper: GET /check?port=N tests that port on your own address.\n"))
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(r.URL.Query().Get("port"))
	switch {
	case ip == nil:
		reply(w, 400, map[string]string{"error": "couldn't tell who you are"})
	case err != nil || port < 1 || port > 65535:
		reply(w, 400, map[string]string{"error": "port must be 1-65535"})
	case !s.allowPrivate && !(ip.IsGlobalUnicast() && !ip.IsPrivate()):
		reply(w, 400, map[string]string{"error": "your address isn't a public internet address"})
	case !s.allow(host):
		reply(w, 429, map[string]string{"error": "rate limit: 10 checks per minute"})
	default:
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		reply(w, 200, map[string]any{"ip": host, "port": port, "open": s.dial(ctx, net.JoinHostPort(host, strconv.Itoa(port)))})
	}
}

func newServer(allowPrivate bool) *server {
	return &server{
		allowPrivate: allowPrivate,
		limit:        10,
		hits:         map[string][]time.Time{},
		dial: func(ctx context.Context, addr string) bool {
			c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			if err != nil {
				return false
			}
			c.Close()
			return true
		},
	}
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()
	log.Printf("portcheck-helper listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, newServer(false)))
}
