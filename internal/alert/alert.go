// Package alert tells people when something changes: a desktop
// notification, a webhook (Discord, Slack, Teams, ntfy or plain JSON), a
// command of their own, or an email.
package alert

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Event is what an alert is about.
type Event struct {
	Time    time.Time     `json:"time"`
	Kind    string        `json:"kind"` // "down", "up", "cert", "test"
	Target  string        `json:"target"`
	Name    string        `json:"name"`
	Text    string        `json:"text"`
	Detail  string        `json:"detail,omitempty"`
	DownFor time.Duration `json:"down_for_ns,omitempty"`
	Host    string        `json:"from"` // the machine watching
}

// Title is a short headline for notifications and mail subjects.
func (e Event) Title() string {
	switch e.Kind {
	case "down":
		return "DOWN: " + e.Name
	case "up":
		return "UP: " + e.Name
	case "cert":
		return "Certificate: " + e.Name
	case "test", "":
		return "netcheck test alert"
	}
	return e.Name // other tools name their own events
}

// Channel is one way of telling.
type Channel interface {
	Name() string
	Send(ctx context.Context, e Event) error
}

// --- desktop ---

// Desktop shows a notification on this machine.
type Desktop struct{}

func (Desktop) Name() string { return "desktop notification" }

// runCmd is a test seam for starting helper programs.
var runCmd = func(ctx context.Context, env []string, name string, args ...string) error {
	c := exec.CommandContext(ctx, name, args...)
	c.Env = append(os.Environ(), env...)
	out, err := c.CombinedOutput()
	if err != nil && len(bytes.TrimSpace(out)) > 0 {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return err
}

// winToast shows a Windows notification through PowerShell's WinRT
// access. Title and text arrive in environment variables and are escaped
// as XML inside the script, so nothing in them runs.
const winToast = `$ErrorActionPreference='Stop'
[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
$t = [Security.SecurityElement]::Escape($env:NETCHECK_TITLE)
$b = [Security.SecurityElement]::Escape($env:NETCHECK_BODY)
$x = New-Object Windows.Data.Xml.Dom.XmlDocument
$x.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>")
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($x))`

func (Desktop) Send(ctx context.Context, e Event) error {
	body := e.Text
	if e.Detail != "" && !strings.Contains(body, e.Detail) {
		body += " (" + e.Detail + ")"
	}
	switch runtime.GOOS {
	case "windows":
		return runCmd(ctx, []string{"NETCHECK_TITLE=" + e.Title(), "NETCHECK_BODY=" + body}, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", winToast)
	case "darwin":
		return runCmd(ctx, nil, "osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", e.Title(), body)
	}
	if _, err := exec.LookPath("notify-send"); err != nil {
		return fmt.Errorf("notify-send isn't installed (it comes with libnotify)")
	}
	urgency := "normal"
	if e.Kind == "down" {
		urgency = "critical"
	}
	return runCmd(ctx, nil, "notify-send", "-u", urgency, "-a", "netcheck", e.Title(), body)
}

// --- webhook ---

// Webhook posts to a URL in the format its service expects.
type Webhook struct {
	URL    string
	client *http.Client
}

func (w Webhook) Name() string {
	if u, err := url.Parse(w.URL); err == nil {
		return "webhook " + u.Host
	}
	return "webhook"
}

// webhookKind recognizes a service by its address.
func webhookKind(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "json"
	}
	h := strings.ToLower(u.Host)
	switch {
	case strings.HasSuffix(h, "discord.com") || strings.HasSuffix(h, "discordapp.com"):
		return "discord"
	case h == "hooks.slack.com":
		return "slack"
	case strings.Contains(h, "webhook.office.com") || strings.Contains(h, "logic.azure.com"):
		return "teams"
	case h == "ntfy.sh" || strings.HasPrefix(h, "ntfy."):
		return "ntfy"
	}
	return "json"
}

// webhookRequest builds the request for a service.
func webhookRequest(ctx context.Context, raw string, e Event) (*http.Request, error) {
	var body []byte
	ctype := "application/json"
	line := e.Title() + ": " + e.Text
	switch webhookKind(raw) {
	case "discord":
		body, _ = json.Marshal(map[string]string{"content": line, "username": "netcheck"})
	case "slack", "teams":
		body, _ = json.Marshal(map[string]string{"text": line})
	case "ntfy":
		body, ctype = []byte(e.Text), "text/plain; charset=utf-8"
	default:
		body, _ = json.Marshal(map[string]any{"text": line, "event": e})
	}
	req, err := http.NewRequestWithContext(ctx, "POST", raw, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", "netcheck-alert")
	if webhookKind(raw) == "ntfy" {
		req.Header.Set("Title", e.Title())
		req.Header.Set("Tags", map[string]string{"down": "rotating_light", "up": "white_check_mark", "cert": "warning"}[e.Kind])
		if e.Kind == "down" {
			req.Header.Set("Priority", "high")
		}
	}
	return req, nil
}

func (w Webhook) Send(ctx context.Context, e Event) error {
	req, err := webhookRequest(ctx, w.URL, e)
	if err != nil {
		return err
	}
	c := w.client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 300))
		return fmt.Errorf("the webhook answered %s: %s", res.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// --- command ---

// Command runs a command of the user's for each alert, through the
// system shell, with the details in NETCHECK_* environment variables.
type Command struct{ Line string }

func (c Command) Name() string { return "command" }

// Env is what the command sees.
func Env(e Event) []string {
	return []string{
		"NETCHECK_EVENT=" + e.Kind, "NETCHECK_TARGET=" + e.Target, "NETCHECK_NAME=" + e.Name,
		"NETCHECK_TEXT=" + e.Text, "NETCHECK_DETAIL=" + e.Detail, "NETCHECK_TIME=" + e.Time.Format(time.RFC3339),
		"NETCHECK_DOWN_FOR=" + strconv.Itoa(int(e.DownFor.Seconds())), "NETCHECK_HOST=" + e.Host,
	}
}

func (c Command) Send(ctx context.Context, e Event) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if runtime.GOOS == "windows" {
		return runCmd(ctx, Env(e), "cmd.exe", "/C", c.Line)
	}
	return runCmd(ctx, Env(e), "sh", "-c", c.Line)
}

// --- email ---

// Email sends through an SMTP server: STARTTLS on 587 and 25, TLS from
// the start on 465. The password comes from NETCHECK_SMTP_PASSWORD.
type Email struct {
	To, From, Server, User, Password string
}

func (m Email) Name() string { return "email to " + m.To }

// message builds the mail.
func (m Email) message(e Event) []byte {
	from := m.From
	if from == "" {
		from = m.User
	}
	id := make([]byte, 8)
	rand.Read(id)
	domain := "netcheck.local"
	if i := strings.LastIndex(from, "@"); i >= 0 {
		domain = from[i+1:]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: netcheck <%s>\r\nTo: %s\r\nSubject: [netcheck] %s\r\n", from, m.To, e.Title())
	fmt.Fprintf(&b, "Date: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n", e.Time.Format(time.RFC1123Z), hex.EncodeToString(id), domain)
	fmt.Fprintf(&b, "%s\r\n\r\n", e.Text)
	fmt.Fprintf(&b, "Target:  %s\r\n", e.Target)
	if e.Detail != "" {
		fmt.Fprintf(&b, "Detail:  %s\r\n", e.Detail)
	}
	if e.DownFor > 0 {
		fmt.Fprintf(&b, "Down for: %s\r\n", e.DownFor.Round(time.Second))
	}
	fmt.Fprintf(&b, "When:    %s\r\nFrom:    %s (netcheck uptime)\r\n", e.Time.Format("2006-01-02 15:04:05 MST"), e.Host)
	return []byte(b.String())
}

// dialSMTP is a test seam.
var dialSMTP = func(ctx context.Context, addr string, implicitTLS bool, host string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 15 * time.Second}
	if implicitTLS {
		return (&tls.Dialer{NetDialer: d, Config: &tls.Config{ServerName: host}}).DialContext(ctx, "tcp", addr)
	}
	return d.DialContext(ctx, "tcp", addr)
}

var smtpTLSConfig = func(host string) *tls.Config { return &tls.Config{ServerName: host} }

func (m Email) Send(ctx context.Context, e Event) error {
	host, port, err := net.SplitHostPort(m.Server)
	if err != nil {
		return fmt.Errorf("the SMTP server is host:port, like smtp.gmail.com:587")
	}
	conn, err := dialSMTP(ctx, m.Server, port == "465", host)
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if port != "465" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("%s doesn't offer STARTTLS; netcheck won't send the password unencrypted", host)
		}
		if err := c.StartTLS(smtpTLSConfig(host)); err != nil {
			return err
		}
	}
	if m.User != "" {
		if err := c.Auth(smtp.PlainAuth("", m.User, m.Password, host)); err != nil {
			return fmt.Errorf("login refused: %v", err)
		}
	}
	from := m.From
	if from == "" {
		from = m.User
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, to := range strings.Split(m.To, ",") {
		if err := c.Rcpt(strings.TrimSpace(to)); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(m.message(e)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	// The server has the message; many hang up on QUIT before TLS says
	// goodbye, which isn't a failure.
	c.Quit()
	return nil
}

// --- configuration ---

// Parse reads one alert setting, as a flag value or an "alert ..." line
// of a servers file (without the word "alert"):
//
//	desktop
//	webhook https://discord.com/api/webhooks/...
//	command notify.sh
//	email me@example.com smtp=smtp.example.com:587 user=me@example.com [from=...]
func Parse(spec string) (Channel, error) {
	kind, rest, _ := strings.Cut(strings.TrimSpace(spec), " ")
	rest = strings.TrimSpace(rest)
	switch strings.ToLower(kind) {
	case "desktop", "notify":
		return Desktop{}, nil
	case "webhook":
		u, err := url.Parse(rest)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("webhook %q: give the webhook's https:// address", rest)
		}
		return Webhook{URL: rest}, nil
	case "command", "cmd":
		if rest == "" {
			return nil, fmt.Errorf("command: give the command to run")
		}
		return Command{Line: rest}, nil
	case "email", "mail":
		f := strings.Fields(rest)
		if len(f) == 0 || !strings.Contains(f[0], "@") {
			return nil, fmt.Errorf("email: give the address to send to, then smtp=host:port user=...")
		}
		m := Email{To: f[0], Password: os.Getenv("NETCHECK_SMTP_PASSWORD")}
		for _, opt := range f[1:] {
			k, v, ok := strings.Cut(opt, "=")
			if !ok {
				return nil, fmt.Errorf("email: %q isn't name=value", opt)
			}
			switch strings.ToLower(k) {
			case "smtp", "server":
				m.Server = v
			case "user":
				m.User = v
			case "from":
				m.From = v
			case "password":
				return nil, fmt.Errorf("email: don't write the password down; set NETCHECK_SMTP_PASSWORD instead")
			default:
				return nil, fmt.Errorf("email: the options are smtp=, user= and from=")
			}
		}
		if m.Server == "" {
			return nil, fmt.Errorf("email: say which server sends it: smtp=host:port")
		}
		if _, _, err := net.SplitHostPort(m.Server); err != nil {
			return nil, fmt.Errorf("email: smtp=%s should be host:port, like smtp.gmail.com:587", m.Server)
		}
		if m.User != "" && m.Password == "" {
			return nil, fmt.Errorf("email: set the password in the NETCHECK_SMTP_PASSWORD environment variable (for Gmail, an app password)")
		}
		if m.From == "" && m.User == "" {
			return nil, fmt.Errorf("email: give user= or from=, the sender's address")
		}
		return m, nil
	}
	return nil, fmt.Errorf("%q: alerts are desktop, webhook URL, command LINE or email ADDRESS smtp=host:port user=...", kind)
}

// Result is one channel's outcome for one event.
type Result struct {
	Channel string `json:"channel"`
	Error   string `json:"error,omitempty"`
}

// Send hands an event to every channel at once and waits for them.
func Send(ctx context.Context, chans []Channel, e Event) []Result {
	if e.Host == "" {
		e.Host, _ = os.Hostname()
	}
	out := make([]Result, len(chans))
	done := make(chan struct{}, len(chans))
	for i, c := range chans {
		go func() {
			defer func() { done <- struct{}{} }()
			out[i] = Result{Channel: c.Name()}
			ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			if err := c.Send(ctx, e); err != nil {
				out[i].Error = err.Error()
			}
		}()
	}
	for range chans {
		<-done
	}
	return out
}
