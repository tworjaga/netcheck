package probe

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// PortMapping is one port the router forwards from the internet because a
// device asked it to over UPnP.
type PortMapping struct {
	Protocol     string `json:"protocol"` // TCP or UDP
	ExternalPort int    `json:"external_port"`
	Client       string `json:"client"` // the LAN device it forwards to
	InternalPort int    `json:"internal_port"`
	Description  string `json:"description,omitempty"`
	Enabled      bool   `json:"enabled"`
	LeaseSeconds int    `json:"lease_seconds"` // 0 = until removed
	RemoteHost   string `json:"remote_host,omitempty"`
}

// maxMappings bounds the walk in case a router never says "no more".
const maxMappings = 256

var soapFieldRe = regexp.MustCompile(`<(New[A-Za-z]+)>\s*([^<]*?)\s*</New[A-Za-z]+>`)

// parseMapping reads a GetGenericPortMappingEntry answer.
func parseMapping(body string) (PortMapping, bool) {
	f := map[string]string{}
	for _, m := range soapFieldRe.FindAllStringSubmatch(body, -1) {
		f[m[1]] = m[2]
	}
	ext, _ := strconv.Atoi(f["NewExternalPort"])
	if ext == 0 || f["NewInternalClient"] == "" {
		return PortMapping{}, false
	}
	in, _ := strconv.Atoi(f["NewInternalPort"])
	lease, _ := strconv.Atoi(f["NewLeaseDuration"])
	return PortMapping{
		Protocol:     strings.ToUpper(f["NewProtocol"]),
		ExternalPort: ext,
		Client:       f["NewInternalClient"],
		InternalPort: in,
		Description:  xmlUnescape(f["NewPortMappingDescription"]),
		Enabled:      f["NewEnabled"] != "0",
		LeaseSeconds: lease,
		RemoteHost:   f["NewRemoteHost"],
	}, true
}

func xmlUnescape(s string) string {
	return strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&").Replace(s)
}

// ErrNoUPnP means the router doesn't answer UPnP, often because it's off.
var ErrNoUPnP = errors.New("router doesn't answer UPnP")

// PortMappings lists the ports the router forwards on behalf of UPnP
// clients. Routers answer index 0, 1, 2… until a fault says there are no
// more.
func PortMappings(ctx context.Context, gw net.IP) ([]PortMapping, error) {
	g, err := findIGD(ctx, gw)
	if err != nil {
		return nil, ErrNoUPnP
	}
	out := []PortMapping{}
	for i := 0; i < maxMappings && ctx.Err() == nil; i++ {
		body, err := g.call(ctx, "GetGenericPortMappingEntry", "<NewPortMappingIndex>"+strconv.Itoa(i)+"</NewPortMappingIndex>")
		if errors.Is(err, errSOAPFault) {
			break // past the last entry
		}
		if err != nil {
			return out, err
		}
		if m, ok := parseMapping(body); ok {
			out = append(out, m)
		}
	}
	return out, ctx.Err()
}
