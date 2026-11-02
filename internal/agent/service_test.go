package agent

import (
	"context"
	"encoding/xml"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/uptime"
)

var svc = Service{Exe: "/opt/net check/netcheck", Args: []string{"agent", "--config", "/home/a/.config/netcheck/agent.json", "--uptime", "/home/a/my servers.txt"}, Log: "/tmp/a&b.log"}

func TestSystemdUnit(t *testing.T) {
	u := SystemdUnit(svc)
	for _, want := range []string{
		`ExecStart="/opt/net check/netcheck" agent --config /home/a/.config/netcheck/agent.json --uptime "/home/a/my servers.txt"`,
		"Restart=always", "WantedBy=default.target", "After=network-online.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("missing %q in\n%s", want, u)
		}
	}
	root := svc
	root.Root = true
	if !strings.Contains(SystemdUnit(root), "WantedBy=multi-user.target") {
		t.Error("a system unit starts at boot")
	}
	if got := systemdQuote([]string{"a$b", "50%"}); got != `"a$$b" "50%%"` {
		t.Errorf("systemd expands $ and %%: %s", got)
	}
}

func TestLaunchdPlist(t *testing.T) {
	p := LaunchdPlist(svc)
	var v struct{}
	if err := xml.Unmarshal([]byte(p), &v); err != nil {
		t.Fatalf("not XML: %v\n%s", err, p)
	}
	for _, want := range []string{"<string>/opt/net check/netcheck</string>", "<string>/home/a/my servers.txt</string>", "<key>KeepAlive</key>", "/tmp/a&amp;b.log"} {
		if !strings.Contains(p, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestTaskXML(t *testing.T) {
	w := Service{Exe: `C:\Users\A B\AppData\Local\Programs\netcheck\netcheck.exe`, Args: []string{"agent", "--config", `C:\Users\A B\AppData\Roaming\netcheck\agent.json`, "--log", `C:\x\agent.log`}}
	x := TaskXML(w, `PC\A B`)
	var task struct {
		Command   string `xml:"Actions>Exec>Command"`
		Arguments string `xml:"Actions>Exec>Arguments"`
		User      string `xml:"Triggers>LogonTrigger>UserId"`
		Limit     string `xml:"Settings>ExecutionTimeLimit"`
		Battery   string `xml:"Settings>DisallowStartIfOnBatteries"`
		Again     string `xml:"Triggers>TimeTrigger>Repetition>Interval"`
		Instances string `xml:"Settings>MultipleInstancesPolicy"`
	}
	// encoding/xml won't read a document that says UTF-16; schtasks gets the real thing.
	if err := xml.Unmarshal([]byte(strings.Replace(x, "UTF-16", "UTF-8", 1)), &task); err != nil {
		t.Fatal(err)
	}
	if task.Command != w.Exe || task.User != `PC\A B` {
		t.Errorf("%+v", task)
	}
	if task.Arguments != `agent --config "C:\Users\A B\AppData\Roaming\netcheck\agent.json" --log C:\x\agent.log` {
		t.Errorf("arguments: %s", task.Arguments)
	}
	if task.Again != "PT5M" || task.Instances != "IgnoreNew" {
		t.Error("a stopped agent is started again, a running one left alone")
	}
	if task.Limit != "PT0S" || task.Battery != "false" {
		t.Error("the agent must not be stopped after 3 days or on battery")
	}
	b := utf16File("a\n")
	if string(b) != "\xff\xfea\x00\r\x00\n\x00" || decodeOutput(b) != "a\r\n" {
		t.Errorf("utf16: %q", b)
	}
}

func TestTaskRunning(t *testing.T) {
	for in, want := range map[string]bool{
		`"\netcheck agent","N/A","Running"`:         true,
		`"\netcheck agent","N/A","Ready"`:           false,
		`"\netcheck agent","N/A","Wird ausgeführt"`: true,
		`"\netcheck agent","N/A","Выполняется"`:     true,
		``: false,
	} {
		if taskRunning(in) != want {
			t.Errorf("%s: want %v", in, want)
		}
	}
}

func TestServiceStateWithFakeCommands(t *testing.T) {
	old := runCmd
	defer func() { runCmd = old }()
	var ran []string
	runCmd = func(name string, args ...string) (string, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		if name == "systemctl" {
			return "active", nil
		}
		if name == "schtasks" {
			return `"\netcheck agent","N/A","Running"`, nil
		}
		return `{ "PID" = 42; }`, nil
	}
	info := ServiceState(false)
	if !info.Running || len(ran) == 0 {
		t.Errorf("%+v %v", info, ran)
	}
}

func TestEnvFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.env")
	if err := SaveEnv(p, map[string]string{"NETCHECK_TEST_PW": "s3cr=t"}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("the env file holds a password; mode %v", st.Mode())
	}
	os.Unsetenv("NETCHECK_TEST_PW")
	defer os.Unsetenv("NETCHECK_TEST_PW")
	LoadEnv(p)
	if os.Getenv("NETCHECK_TEST_PW") != "s3cr=t" {
		t.Errorf("got %q", os.Getenv("NETCHECK_TEST_PW"))
	}
	os.Setenv("NETCHECK_TEST_PW", "from the shell")
	LoadEnv(p)
	if os.Getenv("NETCHECK_TEST_PW") != "from the shell" {
		t.Error("the shell's value wins")
	}
	LoadEnv(filepath.Join(t.TempDir(), "missing"))
}

func TestStatusEndpoint(t *testing.T) {
	since := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	tg := uptime.Target{ID: "https://x.test", Name: "x.test", Kind: "https"}
	s := &Server{Token: "tok", Status: func() Status {
		return Status{Since: since, Tunnel: "https://a-b.trycloudflare.com", Every: time.Minute, Alerts: []string{"desktop"},
			Watch:  []uptime.State{{Target: tg, Down: true, Checks: 4, Good: 1}},
			Events: []uptime.Event{{ID: tg.ID, Kind: "down", Text: "x.test is down"}}}
	}}
	srv := httptest.NewServer(s)
	defer srv.Close()
	st, err := Remote{URL: srv.URL, Token: "tok"}.Status(context.Background())
	if err != nil || !st.Since.Equal(since) || st.Tunnel == "" || st.Every != time.Minute || len(st.Watch) != 1 || !st.Watch[0].Down || st.Watch[0].Target.Name != "x.test" || st.Events[0].Kind != "down" {
		t.Errorf("%+v %v", st, err)
	}
	// Without a watch it still answers.
	srv2 := httptest.NewServer(&Server{Token: "tok"})
	defer srv2.Close()
	if st, err := (Remote{URL: srv2.URL, Token: "tok"}).Status(context.Background()); err != nil || len(st.Watch) != 0 {
		t.Errorf("%+v %v", st, err)
	}
	if _, err := (Remote{URL: srv.URL, Token: "nope"}).Status(context.Background()); err == nil {
		t.Error("status needs the token too")
	}
}

func TestWaitStopped(t *testing.T) {
	oldRun, oldSleep := runCmd, sleep
	defer func() { runCmd, sleep = oldRun, oldSleep }()
	sleep = func(time.Duration) {}
	pid := filepath.Join(t.TempDir(), "agent.pid")
	os.WriteFile(pid, []byte("4242\n"), 0o600)
	var killed []string
	image := `"netcheck.exe","4242","Console","1","20,000 K"`
	runCmd = func(name string, args ...string) (string, error) {
		switch name {
		case "tasklist":
			return image, nil
		case "taskkill":
			killed = append(killed, args[1])
		}
		return "", nil
	}
	waitStopped(pid)
	if len(killed) != 1 || killed[0] != "4242" {
		t.Errorf("an agent that won't stop is ended: %v", killed)
	}
	// The pid now belongs to something else: leave it alone.
	killed, image = nil, `"notepad.exe","4242","Console","1","9,000 K"`
	waitStopped(pid)
	if len(killed) != 0 {
		t.Errorf("killed %v", killed)
	}
	waitStopped(filepath.Join(t.TempDir(), "none.pid"))
}
