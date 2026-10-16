package domain

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// certInfo is what a TLS handshake showed.
type certInfo struct {
	Leaf    *x509.Certificate
	Version uint16
	Problem string // "", "untrusted", "expired", "name"
}

// dialTLS is a test seam: a handshake with host on port 443. A certificate
// that doesn't verify still comes back, with the problem named.
var dialTLS = func(ctx context.Context, host string) (*certInfo, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 6 * time.Second}, Config: &tls.Config{ServerName: host}}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err == nil {
		defer c.Close()
		st := c.(*tls.Conn).ConnectionState()
		return &certInfo{Leaf: st.PeerCertificates[0], Version: st.Version}, nil
	}
	problem := ""
	var name x509.HostnameError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &name):
		problem = "name"
	case errors.As(err, &unknown):
		problem = "untrusted"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		problem = "expired"
	case errors.As(err, &invalid):
		problem = "untrusted"
	default:
		return nil, err
	}
	// Look at the certificate anyway, to say what's wrong with it.
	d.Config = &tls.Config{ServerName: host, InsecureSkipVerify: true}
	c, err2 := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err2 != nil {
		return nil, err
	}
	defer c.Close()
	st := c.(*tls.Conn).ConnectionState()
	return &certInfo{Leaf: st.PeerCertificates[0], Version: st.Version, Problem: problem}, nil
}

var tlsNames = map[uint16]string{tls.VersionTLS10: "TLS 1.0", tls.VersionTLS11: "TLS 1.1", tls.VersionTLS12: "TLS 1.2", tls.VersionTLS13: "TLS 1.3"}

func issuer(c *x509.Certificate) string {
	if len(c.Issuer.Organization) > 0 {
		return c.Issuer.Organization[0]
	}
	return c.Issuer.CommonName
}

// web checks the certificates on the domain and www, returning the fewest
// days left on one that's in use (-1 if none answered).
func web(ctx context.Context, zone string) (int, []Check) {
	hosts := []string{trim(zone), "www." + trim(zone)}
	infos := make([]*certInfo, len(hosts))
	errs := make([]error, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func() { defer wg.Done(); infos[i], errs[i] = dialTLS(ctx, h) }()
	}
	wg.Wait()

	var cs []Check
	days := -1
	for i, h := range hosts {
		in := infos[i]
		if in == nil {
			why := "no HTTPS server answered"
			var dns *net.DNSError
			if errors.As(errs[i], &dns) {
				why = "the name has no address"
			}
			cs = append(cs, Check{AreaWeb, Info, h + ": no HTTPS", why, ""})
			continue
		}
		left := in.Leaf.NotAfter.Sub(now())
		d := int(left.Hours() / 24)
		if days < 0 || d < days {
			days = d
		}
		detail := fmt.Sprintf("%s · %s · until %s", issuer(in.Leaf), tlsNames[in.Version], in.Leaf.NotAfter.UTC().Format("2006-01-02"))
		switch {
		case in.Problem == "expired" || left <= 0:
			cs = append(cs, Check{AreaWeb, Bad, h + ": certificate expired", detail, "Renew the certificate now; browsers block the site until you do."})
		case in.Problem == "name":
			cs = append(cs, Check{AreaWeb, Bad, h + ": certificate is for another name", strings.Join(in.Leaf.DNSNames, ", "),
				"Get a certificate that includes " + h + " (add it to the certificate's names)."})
		case in.Problem == "untrusted":
			cs = append(cs, Check{AreaWeb, Bad, h + ": certificate isn't trusted", detail,
				"Use a certificate from a public authority, and serve the full chain (the intermediate certificates too)."})
		case d < 7:
			cs = append(cs, Check{AreaWeb, Bad, fmt.Sprintf("%s: certificate expires in %s", h, plural(d, "day", "days")), detail,
				"Renew it now, and check why automatic renewal didn't."})
		case d < 21:
			cs = append(cs, Check{AreaWeb, Warn, fmt.Sprintf("%s: certificate expires in %d days", h, d), detail,
				"Renew soon; if renewal is automatic, it should have happened by now."})
		default:
			cs = append(cs, Check{AreaWeb, OK, fmt.Sprintf("%s: valid for %d more days", h, d), detail, ""})
		}
		if in.Version != 0 && in.Version < tls.VersionTLS12 {
			cs = append(cs, Check{AreaWeb, Warn, h + ": old TLS version", tlsNames[in.Version], "Turn on TLS 1.2 and 1.3 on the server."})
		}
	}
	return days, cs
}
