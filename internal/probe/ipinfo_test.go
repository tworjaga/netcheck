package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeTXT(t *testing.T, recs map[string]string) {
	t.Helper()
	old := txtLookup
	txtLookup = func(ctx context.Context, name string) ([]string, error) {
		if v, ok := recs[name]; ok {
			return []string{v}, nil
		}
		return nil, errors.New("nxdomain")
	}
	t.Cleanup(func() { txtLookup = old })
}

func TestCymruASN(t *testing.T) {
	fakeTXT(t, map[string]string{
		"4.3.2.203.origin.asn.cymru.com": "8447 | 203.2.3.0/24 | AT | ripencc | 2001-01-01",
		"AS8447.asn.cymru.com":           "8447 | AT | ripencc | 1996-01-01 | A1TELEKOM-AT A1 Telekom Austria AG, AT",
	})
	info := LookupASN(context.Background(), net.IPv4(203, 2, 3, 4))
	if info.ASN != "AS8447" || info.Source != "cymru" || info.Country != "AT" || !strings.Contains(info.ISP, "A1 Telekom Austria") {
		t.Fatalf("got %+v", info)
	}
	if strings.HasSuffix(info.ISP, ", AT") {
		t.Fatalf("country suffix should be trimmed: %q", info.ISP)
	}
}

func TestASNFallsBackToAPI(t *testing.T) {
	fakeTXT(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip":"9.9.9.9","org":"AS19281 Quad9","country":"US"}`)
	}))
	defer srv.Close()
	old := ipAPIURL
	ipAPIURL = srv.URL + "/%s/json"
	defer func() { ipAPIURL = old }()
	info := LookupASN(context.Background(), net.IPv4(9, 9, 9, 9))
	if info.ASN != "AS19281" || info.ISP != "Quad9" || info.Source != "ipinfo" {
		t.Fatalf("got %+v", info)
	}
}

func TestASNBothFail(t *testing.T) {
	fakeTXT(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer srv.Close()
	old := ipAPIURL
	ipAPIURL = srv.URL + "/%s/json"
	defer func() { ipAPIURL = old }()
	if info := LookupASN(context.Background(), net.IPv4(1, 2, 3, 4)); info.Error == "" {
		t.Fatalf("expected an error, got %+v", info)
	}
}

func TestPublicIPRaceSurvivesDeadEndpoints(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ip=203.0.113.7\nts=1\n") }))
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 503) }))
	defer good.Close()
	defer bad.Close()
	old := publicIPEndpoints
	publicIPEndpoints = []string{bad.URL, "http://127.0.0.1:1", good.URL}
	defer func() { publicIPEndpoints = old }()
	ip, err := PublicIP(context.Background())
	if err != nil || ip.String() != "203.0.113.7" {
		t.Fatalf("got %v %v", ip, err)
	}
}

func TestPublicIPAllFail(t *testing.T) {
	old := publicIPEndpoints
	publicIPEndpoints = []string{"http://127.0.0.1:1"}
	defer func() { publicIPEndpoints = old }()
	if _, err := PublicIP(context.Background()); err == nil {
		t.Fatal("expected failure when offline")
	}
}
