package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/ui"
	"github.com/tworjaga/netcheck/internal/webx"
)

// connectInfo is what was learned from one connection.
type connectInfo struct {
	Target   string        `json:"target"`
	Proto    string        `json:"proto"`
	Remote   string        `json:"remote,omitempty"`
	Connect  time.Duration `json:"connect_ns,omitempty"`
	TLS      string        `json:"tls,omitempty"`
	Cipher   string        `json:"cipher,omitempty"`
	ALPN     string        `json:"alpn,omitempty"`
	Cert     string        `json:"cert,omitempty"`
	CertNote string        `json:"cert_problem,omitempty"`
	Sent     int           `json:"sent"`
	Received string        `json:"received,omitempty"`
	Closed   string        `json:"closed,omitempty"` // "remote", "idle", "you"
	Error    string        `json:"error,omitempty"`
}

// dialConnect is a test seam.
var dialConnect = func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 8 * time.Second}
	return d.DialContext(ctx, network, addr)
}

func connectErr(err error, addr string) string {
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns) && dns.IsNotFound:
		return dns.Name + " doesn't exist"
	case strings.Contains(err.Error(), "refused"):
		return "connection refused: nothing listens on " + addr
	case strings.Contains(err.Error(), "timeout"):
		return "no answer from " + addr + "; a firewall may drop it"
	}
	return err.Error()
}

// openConn connects and, with tlsOn, runs the handshake.
func openConn(ctx context.Context, in *connectInfo, addr string, udp, tlsOn, insecure bool, sni string) (net.Conn, error) {
	network := "tcp"
	if udp {
		network = "udp"
	}
	start := time.Now()
	c, err := dialConnect(ctx, network, addr)
	if err != nil {
		in.Error = connectErr(err, addr)
		return nil, err
	}
	in.Connect, in.Remote = time.Since(start), c.RemoteAddr().String()
	if !tlsOn {
		return c, nil
	}
	host, _, _ := net.SplitHostPort(addr)
	if sni == "" && net.ParseIP(host) == nil {
		sni = host
	}
	// No ALPN: offering h2 makes web servers speak binary HTTP/2, and typed
	// HTTP/1.1 wouldn't work.
	tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		c.Close()
		in.Error = "TLS handshake failed: " + err.Error()
		return nil, err
	}
	st := tc.ConnectionState()
	in.TLS, in.Cipher, in.ALPN = webx.TLSName(st.Version), tls.CipherSuiteName(st.CipherSuite), st.NegotiatedProtocol
	leaf := st.PeerCertificates[0]
	in.Cert = fmt.Sprintf("%s, by %s, until %s", leaf.Subject.CommonName, firstNonEmpty(strings.Join(leaf.Issuer.Organization, ""), leaf.Issuer.CommonName), leaf.NotAfter.Format("2006-01-02"))
	inter := x509.NewCertPool()
	for _, x := range st.PeerCertificates[1:] {
		inter.AddCert(x)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: sni, Intermediates: inter}); err != nil {
		in.CertNote = err.Error()
		if !insecure {
			tc.Close()
			in.Error = "the certificate isn't valid: " + err.Error() + " (-k connects anyway; `netcheck cert` explains)"
			return nil, err
		}
	}
	return tc, nil
}

// isText reports whether b reads as text: no control bytes besides
// tab, CR and LF.
func isText(b []byte) bool {
	for _, c := range b {
		if c < 32 && c != '\t' && c != '\r' && c != '\n' || c == 127 {
			return false
		}
	}
	return true
}

// hexDump shows binary data the way hexdump -C does, first 512 bytes.
func hexDump(b []byte) string {
	var out strings.Builder
	shown := b
	if len(shown) > 512 {
		shown = shown[:512]
	}
	for i := 0; i < len(shown); i += 16 {
		row := shown[i:min(i+16, len(shown))]
		var hx, txt strings.Builder
		for j := 0; j < 16; j++ {
			if j < len(row) {
				fmt.Fprintf(&hx, "%02x ", row[j])
				if row[j] >= 32 && row[j] < 127 {
					txt.WriteByte(row[j])
				} else {
					txt.WriteByte('.')
				}
			} else {
				hx.WriteString("   ")
			}
			if j == 7 {
				hx.WriteByte(' ')
			}
		}
		fmt.Fprintf(&out, "  %04x  %s |%s|\n", i, hx.String(), txt.String())
	}
	if len(b) > len(shown) {
		fmt.Fprintf(&out, "  ... %d more bytes\n", len(b)-len(shown))
	}
	return out.String()
}

// exchange sends what's given, then reads until the other side closes or
// stays quiet for idle.
func exchange(c net.Conn, send []byte, idle time.Duration, out io.Writer, in *connectInfo) {
	if len(send) > 0 {
		n, _ := c.Write(send)
		in.Sent = n
	}
	if cw, ok := c.(interface{ CloseWrite() error }); ok && len(send) > 0 {
		if _, isUDP := c.(*net.UDPConn); !isUDP {
			cw.CloseWrite()
		}
	}
	var got strings.Builder
	buf := make([]byte, 32<<10)
	for {
		c.SetReadDeadline(time.Now().Add(idle))
		n, err := c.Read(buf)
		if n > 0 {
			got.Write(buf[:n])
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				in.Closed = "idle"
			} else {
				in.Closed = "remote"
			}
			break
		}
		if got.Len() > 1<<20 {
			break
		}
	}
	in.Received = got.String()
	if b := []byte(in.Received); out != nil && len(b) > 0 {
		if isText(b) {
			out.Write(b)
		} else {
			fmt.Fprintf(out, "  %s of binary data:\n%s", plural(len(b), "byte", "bytes"), hexDump(b))
		}
	}
}

// interactive copies the other side to the terminal and typed lines to the
// other side, until either ends.
func interactive(ctx context.Context, c net.Conn, crlf bool, in *connectInfo) {
	var once sync.Once
	done := make(chan string, 2)
	finish := func(why string) { once.Do(func() { done <- why }) }
	go func() {
		n, _ := io.Copy(os.Stdout, c)
		in.Received = fmt.Sprintf("%d bytes", n)
		finish("remote")
	}()
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			line := sc.Text()
			if crlf {
				line += "\r\n"
			} else {
				line += "\n"
			}
			n, err := c.Write([]byte(line))
			in.Sent += n
			if err != nil {
				break
			}
		}
		finish("you")
	}()
	select {
	case why := <-done:
		in.Closed = why
	case <-ctx.Done():
		in.Closed = "you"
	}
	c.Close()
}

func connectVerdict(in connectInfo) (ui.Status, string, []string) {
	if in.Error != "" {
		return ui.Bad, "Couldn't connect: " + in.Error + ".", nil
	}
	P := strings.ToUpper(in.Proto)
	msg := fmt.Sprintf("Connected to %s over %s in %s", in.Target, P, fmtMs(float64(in.Connect.Microseconds())/1000))
	if in.Proto == "udp" {
		msg = fmt.Sprintf("Sent %d bytes to %s over UDP", in.Sent, in.Target)
	}
	var notes []string
	first := strings.TrimSpace(strings.SplitN(in.Received, "\n", 2)[0])
	switch {
	case in.Proto == "udp" && in.Received == "":
		msg += "; no answer came back."
		notes = append(notes, "Over UDP, silence doesn't tell: the port may be closed, filtered, or open to a service that ignores what was sent.")
	case first != "" && !isText([]byte(in.Received)):
		msg += fmt.Sprintf("; it answered with %s of binary data", plural(len(in.Received), "byte", "bytes"))
	case first != "" && !strings.HasSuffix(in.Received, " bytes"):
		msg += "; it said: " + ui.Cut(printable(first), 70)
	default:
		msg += "."
	}
	if in.TLS != "" {
		notes = append(notes, fmt.Sprintf("%s · %s · %s", in.TLS, in.Cipher, in.Cert))
	}
	if in.CertNote != "" {
		notes = append(notes, "The certificate isn't valid ("+in.CertNote+"); connected anyway because of -k.")
	}
	if in.Closed == "remote" && in.Proto != "udp" {
		notes = append(notes, "The other side closed the connection.")
	}
	if !strings.HasSuffix(msg, ".") && !strings.HasSuffix(msg, "…") {
		msg += "."
	}
	return ui.OK, msg, notes
}

func cmdConnect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	common := adv.Register(fs)
	udp := fs.Bool("udp", false, "UDP instead of TCP")
	tlsOn := fs.Bool("tls", false, "speak TLS after connecting")
	insecure := fs.Bool("k", false, "with --tls: connect even if the certificate isn't valid")
	sni := fs.String("sni", "", "with --tls: the name to ask for")
	send := fs.String("s", "", "send this (\\r\\n and \\n are understood), then show the answer")
	idle := fs.Duration("w", 3*time.Second, "how long to wait for more data before stopping")
	crlf := fs.Bool("crlf", false, "end typed lines with CRLF (SMTP, HTTP, POP3 and IMAP want that)")
	pos := parseInterspersed(fs, args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	usage := func(msg string) int {
		fmt.Fprintln(os.Stderr, "netcheck connect: "+msg)
		fmt.Fprintln(os.Stderr, "usage: netcheck connect <host:port> [--udp] [--tls] [-s text] [-w 3s] [--crlf]")
		return 2
	}
	if len(pos) != 1 {
		return usage("give host:port")
	}
	host, port, err := net.SplitHostPort(pos[0])
	if err != nil {
		if len(pos) == 1 && strings.Count(pos[0], ":") == 0 {
			return usage("give the port too, like example.com:25")
		}
		return usage(err.Error())
	}
	if *tlsOn && *udp {
		return usage("--tls works over TCP")
	}
	addr := net.JoinHostPort(host, port)
	proto := "tcp"
	if *udp {
		proto = "udp"
	}
	in := connectInfo{Target: addr, Proto: proto}
	payload := strings.NewReplacer(`\r`, "\r", `\n`, "\n", `\t`, "\t").Replace(*send)
	interactiveMode := ui.StdinTTY() && !common.JSON && *send == ""
	if *udp && payload == "" && !interactiveMode {
		payload = "netcheck\n" // UDP needs something to send
	}

	ui.SetQuiet(common.JSON)
	ui.Title("connect")
	c, err := openConn(ctx, &in, addr, *udp, *tlsOn, *insecure, *sni)
	if err != nil {
		st, msg, _ := connectVerdict(in)
		ui.Verdict(st, msg)
		ui.Println("")
		if common.JSON {
			adv.Envelope{Tool: "connect", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: in}.Write(os.Stdout)
		}
		return 1
	}
	defer c.Close()
	head := fmt.Sprintf("Connected to %s in %s", addr, fmtMs(float64(in.Connect.Microseconds())/1000))
	if in.Remote != addr {
		head = fmt.Sprintf("Connected to %s (%s) in %s", addr, in.Remote, fmtMs(float64(in.Connect.Microseconds())/1000))
	}
	if in.TLS != "" {
		head += ", " + in.TLS
	}
	ui.Println("  " + ui.Dim(head))

	if interactiveMode {
		ui.Println("  " + ui.Dim("Type to send; Ctrl-C or Ctrl-Z/Ctrl-D ends.") + "\n")
		interactive(ctx, c, *crlf, &in)
		ui.Println("")
		who := map[string]string{"remote": "The other side closed the connection.", "you": "Closed."}[in.Closed]
		ui.Verdict(ui.OK, who, fmt.Sprintf("Sent %d bytes; received %s.", in.Sent, firstNonEmpty(in.Received, "nothing")))
		ui.Println("")
		return 0
	}
	var body []byte
	if payload != "" {
		body = []byte(payload)
	} else if !ui.StdinTTY() {
		body, _ = io.ReadAll(io.LimitReader(os.Stdin, 8<<20))
	}
	var out io.Writer
	if !common.JSON {
		out = os.Stdout
		ui.Println("")
	}
	exchange(c, body, *idle, out, &in)
	if out != nil && in.Received != "" && !strings.HasSuffix(in.Received, "\n") {
		fmt.Println()
	}
	st, msg, notes := connectVerdict(in)
	ui.Verdict(st, msg, notes...)
	ui.Println("")
	if common.JSON {
		adv.Envelope{Tool: "connect", Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: in}.Write(os.Stdout)
	}
	return 0
}
