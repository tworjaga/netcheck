package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tworjaga/netcheck/internal/agent"
	"github.com/tworjaga/netcheck/internal/alert"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
	"github.com/tworjaga/netcheck/internal/uptime"
)

func agentUsage(msg string) int {
	if msg != "" {
		fmt.Fprintln(os.Stderr, "netcheck agent: "+msg)
	}
	fmt.Fprintln(os.Stderr, `usage:
  on the server:   netcheck agent [--tunnel] [--uptime servers.txt [--every 1m]] [--listen 127.0.0.1:5299] [--rotate-token]
                   netcheck agent install [the same flags]   (a service: starts by itself, restarts if it stops)
                   netcheck agent uninstall | status
  on your machine: netcheck agent add <name> <https://address> <token> [--access-id ID --access-secret SECRET]
                   netcheck agent list | status <name> | remove <name>
  then:            netcheck <check> ... --from <name>   (and netcheck port <port> --from <name>)`)
	return 2
}

func cmdAgent(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "add":
			return agentAdd(args[1:])
		case "list", "ls":
			return agentList(args[1:])
		case "remove", "rm":
			return agentRemove(args[1:])
		case "install":
			return agentInstall(args[1:])
		case "uninstall":
			return agentUninstall(args[1:])
		case "status":
			return agentStatus(args[1:])
		case "help", "-h", "--help":
			return agentUsage("")
		}
	}
	return agentServe(args)
}

// serveFlags are the agent's own settings, shared by agent and agent install.
type serveFlags struct {
	listen, uptimeFile, config, logFile *string
	tunnel, rotate                      *bool
	every                               *time.Duration
}

func addServeFlags(fs *flag.FlagSet) *serveFlags {
	return &serveFlags{
		listen:     fs.String("listen", agent.DefaultListen, "where to listen (this machine only)"),
		tunnel:     fs.Bool("tunnel", false, "start a Cloudflare quick tunnel (needs cloudflared; the address changes on every start)"),
		rotate:     fs.Bool("rotate-token", false, "make a new token (paired machines need it again)"),
		uptimeFile: fs.String("uptime", "", "watch the targets in this file around the clock, with its alert lines (the uptime -f format)"),
		every:      fs.Duration("every", time.Minute, "with --uptime: time between checks"),
		config:     fs.String("config", "", "the agent's settings file (default: agent.json in netcheck's config folder)"),
		logFile:    fs.String("log", "", "write the output to this file instead"),
	}
}

func (f *serveFlags) check() error {
	if err := agent.CheckListen(*f.listen); err != nil {
		return err
	}
	if *f.uptimeFile != "" && *f.every < 5*time.Second {
		return errors.New("--every is at least 5s")
	}
	return nil
}

// agentWatch is uptime running inside the agent.
type agentWatch struct {
	m      *uptime.Monitor
	every  time.Duration
	chans  []alert.Channel
	mu     sync.Mutex
	events []uptime.Event
}

func (w *agentWatch) add(evs []uptime.Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, evs...)
	if len(w.events) > 20 {
		w.events = w.events[len(w.events)-20:]
	}
}

func (w *agentWatch) run(ctx context.Context, logf func(string, ...any)) {
	var hist *uptime.Log
	if p, err := uptime.DefaultPath(); err == nil {
		if hist, err = uptime.OpenLog(p); err != nil {
			logf("can't save the uptime history: %v", err)
		} else {
			defer hist.Close()
		}
	}
	var targets []uptime.Target
	for _, s := range w.m.Snapshot() {
		targets = append(targets, s.Target)
	}
	uptime.Run(ctx, targets, w.every, func(s uptime.Sample) {
		if hist != nil {
			hist.Append(s)
		}
		evs := w.m.Add(s)
		w.add(evs)
		for _, e := range evs {
			logf("%s", e.Text)
			if len(w.chans) == 0 {
				continue
			}
			go func() {
				ae := alert.Event{Time: e.Time, Kind: e.Kind, Target: e.ID, Name: e.Name, Text: e.Text, Detail: e.Detail, DownFor: e.DownFor}
				for _, r := range alert.Send(ctx, w.chans, ae) {
					if r.Error != "" {
						fail := uptime.Event{Time: time.Now(), Kind: "cert", Text: "Alert by " + r.Channel + " failed: " + r.Error}
						w.add([]uptime.Event{fail})
						logf("%s", fail.Text)
					}
				}
			}()
		}
	})
}

// agentServe runs the agent: on 127.0.0.1, for cloudflared to reach.
func agentServe(args []string) int {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	sf := addServeFlags(fs)
	pos := parseInterspersed(fs, args)
	if len(pos) > 0 {
		return agentUsage(fmt.Sprintf("unknown %q", pos[0]))
	}
	if err := sf.check(); err != nil {
		return agentUsage(err.Error())
	}
	if *sf.logFile != "" {
		// Running as a service: the output goes to the log.
		f, err := os.OpenFile(*sf.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return agentUsage(err.Error())
		}
		defer f.Close()
		detachConsole()
		os.Stdout, os.Stderr = f, f
		ui.SetPlain()
	}
	if *sf.config != "" {
		os.Setenv("NETCHECK_AGENT_CONFIG", *sf.config)
	}
	path, err := agent.ConfigPath()
	if err != nil {
		return agentUsage(err.Error())
	}
	agent.LoadEnv(agent.EnvPath(path))
	pidFile := agent.PIDPath(path)
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err == nil {
		defer os.Remove(pidFile)
	}
	cfg, created, err := agent.LoadOrCreate(path, *sf.rotate)
	if err != nil {
		ui.Verdict(ui.Bad, "Couldn't save the agent's token: "+err.Error()+".")
		return 1
	}
	logf := func(format string, a ...any) {
		fmt.Printf("  %s  %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, a...))
	}
	var watch *agentWatch
	if *sf.uptimeFile != "" {
		uptime.UserAgent = "netcheck-uptime/" + version
		targets, chans, err := loadWatchFile(*sf.uptimeFile)
		if err != nil {
			return agentUsage(err.Error())
		}
		watch = &agentWatch{m: uptime.NewMonitor(targets, 3, 14), every: *sf.every, chans: chans}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ln, err := net.Listen("tcp", *sf.listen)
	if err != nil {
		ui.Verdict(ui.Bad, fmt.Sprintf("Couldn't listen on %s: %v.", *sf.listen, err))
		return 1
	}
	ui.Title("agent")
	started := time.Now()
	var tunnelMu sync.Mutex
	tunnelURL := ""
	srv := &agent.Server{Token: cfg.Token, Version: version, OS: runtime.GOOS,
		Log: func(s string) { logf("%s", s) },
		Status: func() agent.Status {
			tunnelMu.Lock()
			st := agent.Status{Since: started, Tunnel: tunnelURL}
			tunnelMu.Unlock()
			if watch != nil {
				st.Every = watch.every
				st.Watch = watch.m.Snapshot()
				for _, c := range watch.chans {
					st.Alerts = append(st.Alerts, c.Name())
				}
				watch.mu.Lock()
				st.Events = append(st.Events, watch.events...)
				watch.mu.Unlock()
			}
			return st
		}}
	hs := &http.Server{Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); hs.Close() }()

	addr := "https://agent.yourdomain.com"
	if *sf.tunnel {
		t := ui.Begin("Starting")
		t.Progress("a Cloudflare quick tunnel…")
		u, done, err := agent.QuickTunnel(ctx, *sf.listen)
		t.Clear()
		if err != nil {
			ln.Close()
			ui.Verdict(ui.Bad, "Couldn't start the tunnel: "+err.Error()+".")
			ui.Println("")
			return 1
		}
		addr = u
		tunnelMu.Lock()
		tunnelURL = u
		tunnelMu.Unlock()
		go func() {
			if err := <-done; ctx.Err() == nil {
				logf("cloudflared stopped (%v); the agent is unreachable until it runs again", err)
			}
		}()
		ui.Println("  " + ui.Good("Tunnel up") + "  " + addr + ui.Dim("  (a quick tunnel: the address changes on every start)"))
	} else {
		ui.Println("  Listening on " + *sf.listen + " for cloudflared. Point a tunnel at it, e.g. in cloudflared's config.yml:")
		ui.Println(ui.Dim("    ingress:"))
		ui.Println(ui.Dim("      - hostname: agent.yourdomain.com"))
		ui.Println(ui.Dim("        service: http://" + *sf.listen))
		ui.Println(ui.Dim("      - service: http_status:404"))
		ui.Println("  " + ui.Dim("Or try it now with --tunnel (a quick tunnel, no account needed)."))
	}
	if watch != nil {
		var names []string
		for _, s := range watch.m.Snapshot() {
			names = append(names, s.Target.Name)
		}
		al := "no alerts"
		if len(watch.chans) > 0 {
			al = "alerts by " + strings.Join(srv.Status().Alerts, ", ")
		}
		ui.Println("  " + ui.Good("Watching") + "  " + strings.Join(names, ", ") + ui.Dim(fmt.Sprintf("  (every %s, %s)", fmtDur(watch.every), al)))
		go watch.run(ctx, logf)
	}
	ui.Println("")
	who := "On your machine, pair once with:"
	if !created {
		who = "Pair a machine with (same token as before; --rotate-token makes a new one):"
	}
	ui.Println("  " + who)
	ui.Println("    " + ui.Bold("netcheck agent add NAME "+addr+" "+cfg.Token))
	ui.Println("  " + ui.Dim("Anyone with this token can run checks from here; keep it like a password. Ctrl-C stops the agent."))
	ui.Println("")
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
		ui.Verdict(ui.Bad, "The agent stopped: "+err.Error()+".")
		return 1
	}
	return 0
}

// agentInstall sets the agent up as a service with the given flags.
func agentInstall(args []string) int {
	fs := flag.NewFlagSet("agent install", flag.ExitOnError)
	sf := addServeFlags(fs)
	pos := parseInterspersed(fs, args)
	if len(pos) > 0 {
		return agentUsage(fmt.Sprintf("unknown %q", pos[0]))
	}
	if err := sf.check(); err != nil {
		return agentUsage(err.Error())
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return agentUsage(err.Error())
	}
	if strings.Contains(exe, "go-build") {
		return agentUsage("build netcheck first (go run's binary is temporary)")
	}
	if *sf.config != "" {
		os.Setenv("NETCHECK_AGENT_CONFIG", *sf.config)
	}
	cfgPath, err := agent.ConfigPath()
	if err == nil {
		cfgPath, err = filepath.Abs(cfgPath)
	}
	if err != nil {
		return agentUsage(err.Error())
	}
	svcArgs := []string{"agent", "--config", cfgPath, "--listen", *sf.listen}
	if *sf.tunnel {
		svcArgs = append(svcArgs, "--tunnel")
	}
	if *sf.uptimeFile != "" {
		p, err := filepath.Abs(*sf.uptimeFile)
		if err != nil {
			return agentUsage(err.Error())
		}
		if _, _, err := loadWatchFile(p); err != nil {
			return agentUsage(err.Error())
		}
		svcArgs = append(svcArgs, "--uptime", p, "--every", sf.every.String())
	}
	logPath := filepath.Join(filepath.Dir(cfgPath), "agent.log")
	if runtime.GOOS == "windows" {
		svcArgs = append(svcArgs, "--log", logPath)
	}
	cfg, _, err := agent.LoadOrCreate(cfgPath, *sf.rotate)
	if err != nil {
		ui.Verdict(ui.Bad, "Couldn't save the agent's token: "+err.Error()+".")
		return 1
	}
	if pw := os.Getenv("NETCHECK_SMTP_PASSWORD"); pw != "" {
		if err := agent.SaveEnv(agent.EnvPath(cfgPath), map[string]string{"NETCHECK_SMTP_PASSWORD": pw}); err != nil {
			ui.Verdict(ui.Bad, "Couldn't save the SMTP password for the service: "+err.Error()+".")
			return 1
		}
	}
	ui.Title("agent install")
	t := ui.Begin("Installing")
	t.Progress("the agent as a service…")
	info, err := agent.Install(agent.Service{Exe: exe, Args: svcArgs, Log: logPath, Root: os.Geteuid() == 0, PID: agent.PIDPath(cfgPath)})
	if err != nil {
		t.Clear()
		ui.Verdict(ui.Bad, "Couldn't install the service: "+err.Error()+".")
		ui.Println("")
		return 1
	}
	// Wait for it to answer (and, with --tunnel, for its address).
	t.Progress("waiting for the agent to answer…")
	local := agent.Remote{URL: "http://" + *sf.listen, Token: cfg.Token}
	var st agent.Status
	answered := false
	wait := 15 * time.Second
	if *sf.tunnel {
		wait = time.Minute
	}
	for end := time.Now().Add(wait); time.Now().Before(end); time.Sleep(time.Second) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		s, err := local.Status(ctx)
		cancel()
		if err == nil {
			answered, st = true, s
			if !*sf.tunnel || s.Tunnel != "" {
				break
			}
		}
	}
	t.Clear()
	if info.Logs == "" {
		info.Logs = logPath
	}
	ui.Open("Service")
	ui.Println(agentKV("Where", info.Where))
	ui.Println(agentKV("Runs", ui.Dim(exe+" "+strings.Join(svcArgs, " "))))
	ui.Println(agentKV("Output", info.Logs))
	ui.Close()
	if !answered {
		ui.Verdict(ui.Bad, "The service is installed but the agent doesn't answer on "+*sf.listen+".",
			append([]string{"Look at its output: " + info.Logs + "."}, info.Notes...)...)
		ui.Println("")
		return 1
	}
	notes := info.Notes
	if *sf.tunnel {
		notes = append(notes, "A quick tunnel's address changes whenever the agent restarts; pair again then, or give it a fixed address with a named tunnel (below without --tunnel).")
	}
	if *sf.uptimeFile != "" {
		notes = append(notes, "netcheck agent status shows what it watches; netcheck uptime --report here sums up the history.")
	}
	ui.Verdict(ui.OK, "The agent runs as a service and starts by itself from now on.", notes...)
	ui.Println("")
	addr := st.Tunnel
	if addr == "" {
		addr = "https://agent.yourdomain.com"
		ui.Println("  Give it a fixed address with a named Cloudflare Tunnel (free; needs a domain on Cloudflare):")
		ui.Println("    1. Cloudflare dashboard, Zero Trust, Networks, Tunnels: create a tunnel (cloudflared).")
		ui.Println("    2. Add a public hostname, e.g. agent.yourdomain.com, with the service http://" + *sf.listen + ".")
		ui.Println("    3. Run the command it shows on this machine: " + ui.Bold("cloudflared service install <tunnel token>"))
		ui.Println("       " + ui.Dim("(cloudflared then runs as its own service and starts by itself too)."))
		ui.Println("")
	}
	ui.Println("  On your machine, pair once with:")
	ui.Println("    " + ui.Bold("netcheck agent add NAME "+addr+" "+cfg.Token))
	ui.Println("")
	return 0
}

// upFor rounds how long the agent has run, to seconds for the first hour.
func upFor(d time.Duration) time.Duration {
	if d < time.Hour {
		return d.Round(time.Second)
	}
	return d.Round(time.Minute)
}

func agentKV(k, v string) string { return ui.Dim(fmt.Sprintf("%-8s", k)) + " " + v }

func agentUninstall(args []string) int {
	if len(args) > 0 {
		return agentUsage("uninstall takes nothing")
	}
	cfgPath, err := agent.ConfigPath()
	if err != nil {
		return agentUsage(err.Error())
	}
	ui.Title("agent uninstall")
	if err := agent.Uninstall(os.Geteuid() == 0, agent.PIDPath(cfgPath)); err != nil {
		ui.Verdict(ui.Bad, "Couldn't remove the service: "+err.Error()+".")
		ui.Println("")
		return 1
	}
	ui.Verdict(ui.OK, "The agent service is stopped and removed.", "Its token stays in agent.json, so paired machines work again if you reinstall; --rotate-token makes a new one.")
	ui.Println("")
	return 0
}

// agentStatus shows an agent: this machine's (and its service), or a
// paired one by name.
func agentStatus(args []string) int {
	fs := flag.NewFlagSet("agent status", flag.ExitOnError)
	listen := fs.String("listen", agent.DefaultListen, "where this machine's agent listens")
	asJSON := fs.Bool("json", false, "print JSON")
	pos := parseInterspersed(fs, args)
	if len(pos) > 1 {
		return agentUsage("status takes at most one agent name")
	}
	ui.SetQuiet(*asJSON)
	var r agent.Remote
	var svc *agent.ServiceInfo
	name := "this machine"
	if len(pos) == 1 {
		var err error
		if r, err = findRemote(pos[0]); err != nil {
			return agentUsage(err.Error())
		}
		name = pos[0]
	} else {
		info := agent.ServiceState(os.Geteuid() == 0)
		svc = &info
		path, err := agent.ConfigPath()
		if err != nil {
			return agentUsage(err.Error())
		}
		cfg, err := agent.LoadConfig(path)
		if err != nil && !info.Installed {
			ui.Title("agent status")
			ui.Verdict(ui.Bad, "No agent is set up on this machine. Start one with netcheck agent, or install it as a service with netcheck agent install.")
			ui.Println("")
			return 1
		}
		r = agent.Remote{URL: "http://" + *listen, Token: cfg.Token}
	}
	ui.Title("agent status")
	t := ui.Begin("Asking")
	t.Progress("the agent on " + name + "…")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	h, herr := r.Hello(ctx)
	var st agent.Status
	if herr == nil {
		st, herr = r.Status(ctx)
	}
	t.Clear()
	if *asJSON {
		out := map[string]any{"agent": name, "answers": herr == nil}
		if herr != nil {
			out["error"] = herr.Error()
		} else {
			out["hello"], out["status"] = h, st
		}
		if svc != nil {
			out["service"] = svc
		}
		printJSON(out)
	}
	ui.Open("Agent")
	if svc != nil {
		state := ui.Dim("not installed (netcheck agent install sets it up)")
		switch {
		case svc.Installed && svc.Running:
			state = ui.Good("running") + ui.Dim("  "+svc.Where)
		case svc.Installed:
			state = ui.Caution("installed, not running") + ui.Dim("  "+svc.Where)
		}
		ui.Println(agentKV("Service", state))
	}
	if herr == nil {
		ui.Println(agentKV("Host", fmt.Sprintf("%s · %s · netcheck %s", h.Host, h.OS, h.Version)))
		ui.Println(agentKV("Up", fmtDur(upFor(time.Since(st.Since)))+ui.Dim("  since "+st.Since.Local().Format("2006-01-02 15:04"))))
		if st.Tunnel != "" {
			ui.Println(agentKV("Tunnel", st.Tunnel+ui.Dim("  (quick tunnel)")))
		}
		if len(st.Watch) > 0 {
			al := "none"
			if len(st.Alerts) > 0 {
				al = strings.Join(st.Alerts, ", ")
			}
			ui.Println(agentKV("Alerts", al))
		}
	}
	ui.Close()
	if herr != nil {
		ui.Verdict(ui.Bad, "The agent doesn't answer: "+herr.Error()+".")
		ui.Println("")
		return 1
	}
	if len(st.Watch) > 0 {
		ui.Open(fmt.Sprintf("Watching every %s", fmtDur(st.Every)))
		for _, l := range uptimeTable(st.Watch, ui.PanelWidth(), time.Now(), false).Lines(ui.PanelWidth()) {
			ui.Println(l)
		}
		ui.Close()
	}
	if len(st.Events) > 0 {
		ui.Open("Recent changes")
		evs := st.Events
		if len(evs) > 8 {
			evs = evs[len(evs)-8:]
		}
		for _, e := range evs {
			ui.Println(eventStatus(e).Paint(e.Time.Local().Format("01-02 15:04")) + "  " + ui.Cut(e.Text, ui.PanelWidth()-16))
		}
		ui.Close()
	}
	down := 0
	for _, s := range st.Watch {
		if s.Down {
			down++
		}
	}
	switch {
	case len(st.Watch) == 0:
		ui.Verdict(ui.OK, "The agent answers. It watches nothing around the clock; give it --uptime servers.txt for that.")
	case down > 0:
		ui.Verdict(ui.Bad, fmt.Sprintf("The agent answers; %d of %s %s down.", down, plural(len(st.Watch), "target", "targets"), map[bool]string{true: "is", false: "are"}[down == 1]))
		ui.Println("")
		return 1
	case len(st.Watch) == 1:
		ui.Verdict(ui.OK, "The agent answers; the target is up.")
	default:
		ui.Verdict(ui.OK, fmt.Sprintf("The agent answers; all %s are up.", plural(len(st.Watch), "target", "targets")))
	}
	ui.Println("")
	return 0
}

func loadRemotes() (agent.Remotes, string, error) {
	p, err := agent.RemotesPath()
	if err != nil {
		return nil, "", err
	}
	r, err := agent.LoadRemotes(p)
	return r, p, err
}

func agentAdd(args []string) int {
	fs := flag.NewFlagSet("agent add", flag.ExitOnError)
	id := fs.String("access-id", "", "Cloudflare Access service token: client ID")
	secret := fs.String("access-secret", "", "Cloudflare Access service token: client secret")
	pos := parseInterspersed(fs, args)
	if len(pos) != 3 {
		return agentUsage("add takes a name, the agent's address and its token")
	}
	u, err := agent.CheckURL(pos[1])
	if err != nil {
		return agentUsage(err.Error())
	}
	r := agent.Remote{Name: pos[0], URL: u, Token: pos[2], AccessID: *id, AccessSecret: *secret}
	ui.Title("agent")
	t := ui.Begin("Pairing")
	t.Progress("with " + u + "…")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, err := r.Hello(ctx)
	t.Clear()
	if err != nil {
		ui.Verdict(ui.Bad, "Couldn't pair: "+err.Error()+".")
		ui.Println("")
		return 1
	}
	rs, path, err := loadRemotes()
	if err != nil {
		ui.Verdict(ui.Bad, "Couldn't read the agents list: "+err.Error()+".")
		return 1
	}
	rs[r.Name] = r
	if err := rs.Save(path); err != nil {
		ui.Verdict(ui.Bad, "Couldn't save the agents list: "+err.Error()+".")
		return 1
	}
	ui.Verdict(ui.OK, fmt.Sprintf("Paired with %s: %s on %s, netcheck %s.", r.Name, h.Host, h.OS, h.Version),
		fmt.Sprintf("Run checks from there with --from %s, e.g. netcheck http example.com --from %s, or netcheck port 8080 --from %s.", r.Name, r.Name, r.Name),
		"The agent sees this machine at "+h.Caller+".")
	ui.Println("")
	return 0
}

func agentList(args []string) int {
	rs, _, err := loadRemotes()
	if err != nil {
		return agentUsage(err.Error())
	}
	ui.Title("agent")
	if len(rs) == 0 {
		ui.Verdict(ui.Skip, "No agents yet. On a server, run netcheck agent --tunnel; it prints the netcheck agent add line for this machine.")
		ui.Println("")
		return 0
	}
	tb := ui.Table{Headers: []string{"Name", "Address", "Agent", "Answers"}}
	for _, n := range rs.Names() {
		r := rs[n]
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		start := time.Now()
		h, err := r.Hello(ctx)
		cancel()
		st, who, ans := ui.OK, fmt.Sprintf("%s · %s · %s", h.Host, h.OS, h.Version), fmtMs(float64(time.Since(start).Microseconds())/1000)
		if err != nil {
			st, who, ans = ui.Bad, "", ui.Dim(ui.Cut(err.Error(), 40))
		}
		tb.Rows = append(tb.Rows, ui.TableRow{Status: st, Cells: []string{n, ui.Cut(r.URL, 34), who, ans}})
	}
	for _, l := range tb.Lines(ui.PanelWidth()) {
		ui.Println(l)
	}
	ui.Println("")
	return 0
}

func agentRemove(args []string) int {
	if len(args) != 1 {
		return agentUsage("remove takes the agent's name")
	}
	rs, path, err := loadRemotes()
	if err != nil {
		return agentUsage(err.Error())
	}
	if _, ok := rs[args[0]]; !ok {
		return agentUsage(fmt.Sprintf("no agent named %q", args[0]))
	}
	delete(rs, args[0])
	if err := rs.Save(path); err != nil {
		return agentUsage(err.Error())
	}
	fmt.Println("Removed " + args[0] + ".")
	return 0
}

// splitFrom takes --from NAME (or --from=NAME) out of the arguments.
func splitFrom(args []string) (string, []string) {
	var rest []string
	from := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--from" || a == "-from":
			if i+1 < len(args) {
				from = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--from=") || strings.HasPrefix(a, "-from="):
			from = a[strings.Index(a, "=")+1:]
		default:
			rest = append(rest, a)
		}
	}
	return from, rest
}

// findRemote looks an agent up by name.
func findRemote(name string) (agent.Remote, error) {
	rs, _, err := loadRemotes()
	if err != nil {
		return agent.Remote{}, err
	}
	r, ok := rs[name]
	if !ok {
		if len(rs) == 0 {
			return r, fmt.Errorf("no agent named %q; pair one first with netcheck agent add", name)
		}
		return r, fmt.Errorf("no agent named %q (known: %s)", name, strings.Join(rs.Names(), ", "))
	}
	return r, nil
}

// runRemote runs a check on an agent and prints what it printed.
func runRemote(tool, name string, args []string) int {
	r, err := findRemote(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "netcheck: "+err.Error())
		return 2
	}
	asJSON := false
	var pass []string
	for _, a := range args {
		if a == "--json" || a == "-json" {
			asJSON = true
			continue
		}
		pass = append(pass, a)
	}
	if err := agent.CheckArgs(tool, pass); err != nil {
		fmt.Fprintln(os.Stderr, "netcheck: "+err.Error())
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var t *ui.Task
	if !asJSON {
		t = ui.Begin("Asking")
		t.Progress(fmt.Sprintf("agent %s to run %s…", name, tool))
	}
	res, err := r.Run(ctx, tool, pass, asJSON)
	if t != nil {
		t.Clear()
	}
	if ctx.Err() != nil {
		return 130
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "netcheck: "+err.Error())
		return 1
	}
	if asJSON {
		fmt.Print(res.Output)
		return res.Exit
	}
	took := fmtMs(float64(res.Took.Microseconds()) / 1000)
	if res.Took >= time.Second {
		took = fmtDur(res.Took.Round(100 * time.Millisecond))
	}
	fmt.Println("\n  " + ui.Dim(fmt.Sprintf("ran on agent %s (%s) in %s", name, res.Host, took)))
	fmt.Print(res.Output)
	return res.Exit
}

// agentExternal is port's outside test through an agent.
func agentExternal(name string) (func(context.Context, int) probe.ExternalResult, error) {
	r, err := findRemote(name)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, port int) probe.ExternalResult {
		res, err := r.Port(ctx, port)
		out := probe.ExternalResult{Helper: "agent " + name, IP: res.IP, Port: port, Open: res.Open, Error: res.Error}
		if err != nil {
			out.Error = err.Error()
		}
		return out
	}, nil
}
