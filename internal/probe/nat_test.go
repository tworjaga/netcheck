package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func ip(s string) net.IP { return net.ParseIP(s) }

func TestClassifyNAT(t *testing.T) {
	cases := []struct{ wan, pub, kind string }{
		{"84.1.2.3", "84.1.2.3", "none"},
		{"100.72.5.9", "84.1.2.3", "cgnat"},
		{"10.0.0.2", "84.1.2.3", "double"},
		{"192.168.0.5", "84.1.2.3", "double"},
		{"84.1.2.3", "84.9.9.9", "cgnat"},
	}
	for _, c := range cases {
		if got := ClassifyNAT(ip(c.wan), ip(c.pub)); got.Kind != c.kind || got.Detail == "" {
			t.Errorf("%s vs %s: got %+v, want %s", c.wan, c.pub, got, c.kind)
		}
	}
}

func TestNATFromHops(t *testing.T) {
	gw := ip("192.168.1.1")
	if n := NATFromHops(gw, []net.IP{gw, ip("100.64.3.1"), ip("84.1.1.1")}); n.Kind != "cgnat" {
		t.Errorf("got %+v", n)
	}
	if n := NATFromHops(gw, []net.IP{gw, ip("10.20.0.1")}); n.Kind != "double" {
		t.Errorf("got %+v", n)
	}
	if n := NATFromHops(gw, []net.IP{gw, ip("84.116.1.1")}); n.Kind != "none" {
		t.Errorf("got %+v", n)
	}
	if n := NATFromHops(gw, []net.IP{gw, nil, nil}); n.Kind != "unknown" {
		t.Errorf("got %+v", n)
	}
}

// fakeIGD serves a UPnP device description and a SOAP endpoint, and answers
// SSDP searches on localhost, so RouterWANIP runs end to end without a router.
func fakeIGD(t *testing.T, wan string) (stop func()) {
	t.Helper()
	oldWait := ssdpWait
	ssdpWait = 250 * time.Millisecond
	mux := http.NewServeMux()
	mux.HandleFunc("/desc.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0"?><root><device><deviceList><device><deviceList><device><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl</controlURL></service></serviceList></device></deviceList></device></deviceList></device></root>`)
	})
	mux.HandleFunc("/ctl", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("SOAPAction") == "" {
			http.Error(w, "no action", 400)
			return
		}
		if strings.Contains(r.Header.Get("SOAPAction"), "GetGenericPortMappingEntry") {
			b, _ := io.ReadAll(r.Body)
			m := regexp.MustCompile(`<NewPortMappingIndex>(\d+)<`).FindSubmatch(b)
			i, _ := strconv.Atoi(string(m[1]))
			if i >= len(igdMappings) {
				w.WriteHeader(500)
				fmt.Fprint(w, fault713)
				return
			}
			fmt.Fprint(w, igdMappings[i])
			return
		}
		fmt.Fprintf(w, `<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>%s</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`, wan)
	})
	srv := httptest.NewServer(mux)

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:fake\r\nSERVER: Fake/1.0 UPnP/1.1\r\nLOCATION: " + srv.URL + "/desc.xml\r\n\r\n"
			_, _ = pc.WriteTo([]byte(resp), from)
		}
	}()
	old := ssdpGroup
	ssdpGroup = pc.LocalAddr().String()
	return func() { ssdpGroup = old; ssdpWait = oldWait; pc.Close(); srv.Close() }
}

func TestRouterWANIPViaUPnP(t *testing.T) {
	defer fakeIGD(t, "100.66.1.2")()
	wan, err := RouterWANIP(context.Background(), ip("127.0.0.1"))
	if err != nil || wan.String() != "100.66.1.2" {
		t.Fatalf("got %v %v", wan, err)
	}
	n := DetectNAT(context.Background(), ip("127.0.0.1"), ip("84.1.2.3"), nil)
	if n.Kind != "cgnat" || n.Method != "upnp" {
		t.Fatalf("got %+v", n)
	}
}

func TestRouterWANIPIgnoresOtherDevices(t *testing.T) {
	defer fakeIGD(t, "84.1.2.3")()
	if _, err := RouterWANIP(context.Background(), ip("10.9.9.9")); err == nil {
		t.Fatal("must not trust a UPnP answer from a device that isn't the gateway")
	}
}

func TestDetectNATFallsBackToRoute(t *testing.T) {
	old, oldWait := ssdpGroup, ssdpWait
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0") // listens, never answers
	ssdpGroup, ssdpWait = pc.LocalAddr().String(), 250*time.Millisecond
	defer func() { ssdpGroup, ssdpWait = old, oldWait; pc.Close() }()
	hops := func(context.Context) []net.IP { return []net.IP{ip("192.168.1.1"), ip("100.64.0.1")} }
	n := DetectNAT(context.Background(), ip("192.168.1.1"), ip("84.1.2.3"), hops)
	if n.Kind != "cgnat" || n.Method != "route" {
		t.Fatalf("got %+v", n)
	}
	n = DetectNAT(context.Background(), ip("192.168.1.1"), ip("84.1.2.3"), nil)
	if n.Kind != "unknown" {
		t.Fatalf("got %+v", n)
	}
}

// fault713 is what a real router (192.168.0.1, miniupnpd-style) answered for
// a mapping index past the end of its table.
const fault713 = `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>713</errorCode><errorDescription>SpecifiedArrayIndexInvalid</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`

// igdMappings are the GetGenericPortMappingEntry answers fakeIGD serves.
var igdMappings []string

func mappingResponse(proto string, ext int, client string, in int, desc string, enabled, lease int) string {
	return fmt.Sprintf(`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>%s</NewProtocol><NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>%d</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>%d</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>`,
		ext, proto, in, client, enabled, desc, lease)
}

func TestPortMappingsWalksTheTable(t *testing.T) {
	igdMappings = []string{
		mappingResponse("UDP", 3074, "192.168.0.38", 3074, "Xbox (3074) &amp; party", 1, 0),
		mappingResponse("TCP", 32400, "192.168.0.202", 32400, "Plex Media Server", 1, 7200),
	}
	defer func() { igdMappings = nil }()
	defer fakeIGD(t, "84.1.2.3")()
	ms, err := PortMappings(context.Background(), ip("127.0.0.1"))
	if err != nil || len(ms) != 2 {
		t.Fatalf("got %+v %v", ms, err)
	}
	if m := ms[0]; m.Protocol != "UDP" || m.ExternalPort != 3074 || m.Client != "192.168.0.38" || m.Description != "Xbox (3074) & party" || !m.Enabled || m.LeaseSeconds != 0 {
		t.Errorf("first: %+v", m)
	}
	if m := ms[1]; m.Protocol != "TCP" || m.InternalPort != 32400 || m.LeaseSeconds != 7200 {
		t.Errorf("second: %+v", m)
	}
}

func TestPortMappingsEmptyTable(t *testing.T) {
	// The real router this was checked on: UPnP on, fault 713 at index 0.
	defer fakeIGD(t, "84.1.2.3")()
	ms, err := PortMappings(context.Background(), ip("127.0.0.1"))
	if err != nil || ms == nil || len(ms) != 0 {
		t.Fatalf("got %+v %v", ms, err)
	}
}

func TestPortMappingsWithoutUPnP(t *testing.T) {
	old, oldWait := ssdpGroup, ssdpWait
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0") // listens, never answers
	ssdpGroup, ssdpWait = pc.LocalAddr().String(), 250*time.Millisecond
	defer func() { ssdpGroup, ssdpWait = old, oldWait; pc.Close() }()
	if _, err := PortMappings(context.Background(), ip("192.168.1.1")); err != ErrNoUPnP {
		t.Fatalf("got %v", err)
	}
}
