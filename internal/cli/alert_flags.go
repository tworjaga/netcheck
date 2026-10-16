package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/adv"
	"github.com/tworjaga/netcheck/internal/alert"
	"github.com/tworjaga/netcheck/internal/ui"
)

// alertFlags are the alert options the watching tools (uptime, lanwatch)
// share.
type alertFlags struct {
	notify                                  *bool
	webhooks                                multiFlag
	cmd, emailTo, smtp, smtpUser, emailFrom *string
	test                                    *bool
}

func addAlertFlags(fs *flag.FlagSet) *alertFlags {
	a := &alertFlags{}
	a.notify = fs.Bool("notify", false, "alert with a desktop notification")
	fs.Var(&a.webhooks, "webhook", "alert by posting to this URL: Discord, Slack, Teams, ntfy or plain JSON (repeatable)")
	a.cmd = fs.String("alert-cmd", "", "alert by running this command (details in NETCHECK_* variables)")
	a.emailTo = fs.String("email", "", "alert by email to this address (with --smtp and --smtp-user)")
	a.smtp = fs.String("smtp", "", "with --email: the mail server, host:port (587 STARTTLS or 465 TLS)")
	a.smtpUser = fs.String("smtp-user", "", "with --email: the login; the password comes from NETCHECK_SMTP_PASSWORD")
	a.emailFrom = fs.String("email-from", "", "with --email: the sender (default: the login)")
	a.test = fs.Bool("test-alert", false, "send a test alert through every channel and stop")
	return a
}

// specs are the flags as alert settings, in the "alert ..." line form.
func (a *alertFlags) specs() []string {
	var out []string
	if *a.notify {
		out = append(out, "desktop")
	}
	for _, w := range a.webhooks {
		out = append(out, "webhook "+w)
	}
	if *a.cmd != "" {
		out = append(out, "command "+*a.cmd)
	}
	if *a.emailTo != "" {
		e := "email " + *a.emailTo + " smtp=" + *a.smtp
		if *a.smtpUser != "" {
			e += " user=" + *a.smtpUser
		}
		if *a.emailFrom != "" {
			e += " from=" + *a.emailFrom
		}
		out = append(out, e)
	}
	return out
}

// splitAlertLines separates "alert ..." lines from the rest of a file.
func splitAlertLines(lines []string) (rest, specs []string) {
	for _, l := range lines {
		if s, ok := strings.CutPrefix(l, "alert "); ok {
			specs = append(specs, s)
		} else {
			rest = append(rest, l)
		}
	}
	return rest, specs
}

func buildChannels(specs []string) ([]alert.Channel, error) {
	var chans []alert.Channel
	for _, sp := range specs {
		c, err := alert.Parse(sp)
		if err != nil {
			return nil, err
		}
		chans = append(chans, c)
	}
	return chans, nil
}

// runTestAlert sends a test through every channel and reports each.
func runTestAlert(ctx context.Context, tool string, chans []alert.Channel, asJSON bool) int {
	ui.SetQuiet(asJSON)
	ui.Title(tool)
	if len(chans) == 0 {
		fmt.Fprintln(os.Stderr, "netcheck "+tool+": --test-alert needs an alert: --notify, --webhook URL, --alert-cmd or --email")
		return 2
	}
	rs := alert.Send(ctx, chans, alert.Event{Time: time.Now(), Kind: "test", Target: "test", Name: "test", Text: "This is a test alert from netcheck " + tool + ". If you see it, alerts reach you."})
	failed := 0
	for _, r := range rs {
		if r.Error != "" {
			failed++
			ui.Println("  " + ui.Bad.Sym() + "  " + r.Channel + ui.Dim(": "+r.Error))
		} else {
			ui.Println("  " + ui.OK.Sym() + "  " + r.Channel)
		}
	}
	st, msg := ui.OK, fmt.Sprintf("Sent a test alert through %s.", plural(len(rs), "channel", "channels"))
	if failed > 0 {
		st, msg = ui.Bad, fmt.Sprintf("%d of %s failed.", failed, plural(len(rs), "channel", "channels"))
	}
	ui.Verdict(st, msg, "Check that it arrived: a sent alert isn't always a delivered one (spam folders, notification settings).")
	ui.Println("")
	if asJSON {
		adv.Envelope{Tool: tool, Version: version, Time: time.Now(), Verdict: adv.Finding{Status: st.String(), Message: msg}, Data: rs}.Write(os.Stdout)
	}
	return adv.ExitCode(st.String(), nil)
}

// multiFlag collects a flag given more than once.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
