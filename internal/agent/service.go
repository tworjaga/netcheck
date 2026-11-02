package agent

import (
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

// The agent as a service: started at boot (or sign-in) and restarted if
// it stops. systemd on Linux, launchd on macOS, Task Scheduler on
// Windows; each as this user, so it finds the same settings.

// ServiceName names the service everywhere.
const ServiceName = "netcheck-agent"

const (
	launchdLabel = "com.netcheck.agent"
	taskName     = "netcheck agent"
)

// Service is what to run.
type Service struct {
	Exe  string
	Args []string
	Log  string // where the output goes (launchd, Task Scheduler)
	Root bool   // installed for the whole machine (Linux, macOS as root)
	PID  string // the agent's pid file, to make sure it stopped (Windows)
}

// ServiceInfo says where the service is and how it's doing.
type ServiceInfo struct {
	Installed bool
	Running   bool
	Where     string // the unit, plist or task
	Logs      string // how to read the output
	Notes     []string
}

// runCmd is a test seam.
var runCmd = func(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	s := strings.TrimSpace(decodeOutput(out))
	if err != nil && s != "" {
		err = fmt.Errorf("%s: %s", name, firstLine(s))
	}
	return s, err
}

// decodeOutput reads schtasks' output, which may be UTF-16.
func decodeOutput(b []byte) string {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		u := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return string(utf16.Decode(u))
	}
	return string(b)
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(l)
}

// SystemdUnit is the unit file.
func SystemdUnit(s Service) string {
	want := "default.target"
	if s.Root {
		want = "multi-user.target"
	}
	return `[Unit]
Description=netcheck agent (checks from this machine, through cloudflared)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + systemdQuote(append([]string{s.Exe}, s.Args...)) + `
Restart=always
RestartSec=10

[Install]
WantedBy=` + want + "\n"
}

func systemdQuote(words []string) string {
	var out []string
	for _, w := range words {
		if w == "" || strings.ContainsAny(w, " \t\"'\\$%") {
			w = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `$$`, `%`, `%%`).Replace(w) + `"`
		}
		out = append(out, w)
	}
	return strings.Join(out, " ")
}

// LaunchdPlist is the launchd job.
func LaunchdPlist(s Service) string {
	var args strings.Builder
	for _, a := range append([]string{s.Exe}, s.Args...) {
		args.WriteString("\t\t<string>" + html.EscapeString(a) + "</string>\n")
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + launchdLabel + `</string>
	<key>ProgramArguments</key>
	<array>
` + args.String() + `	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>` + html.EscapeString(s.Log) + `</string>
	<key>StandardErrorPath</key>
	<string>` + html.EscapeString(s.Log) + `</string>
</dict>
</plist>
`
}

// TaskXML is the Task Scheduler task: at this user's sign-in, and every
// 5 minutes, which starts it again if it stopped (a running agent makes
// the extra starts no-ops); never stopped for running long or on battery.
func TaskXML(s Service, user string) string {
	var args []string
	for _, a := range s.Args {
		if a == "" || strings.ContainsAny(a, " \t\"") {
			a = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
		}
		args = append(args, a)
	}
	e := html.EscapeString
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>netcheck agent: checks from this machine, through cloudflared</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + e(user) + `</UserId>
    </LogonTrigger>
    <TimeTrigger>
      <Repetition>
        <Interval>PT5M</Interval>
      </Repetition>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + e(user) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + e(s.Exe) + `</Command>
      <Arguments>` + e(strings.Join(args, " ")) + `</Arguments>
    </Exec>
  </Actions>
</Task>
`
}

// utf16File is the task XML as schtasks reads it best.
func utf16File(s string) []byte {
	u := utf16.Encode([]rune(strings.ReplaceAll(s, "\n", "\r\n")))
	b := []byte{0xff, 0xfe}
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}

func systemdPath(root bool) (string, error) {
	if root {
		return "/etc/systemd/system/" + ServiceName + ".service", nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "systemd", "user", ServiceName+".service"), nil
}

func launchdPath(root bool) (string, error) {
	if root {
		return "/Library/LaunchDaemons/" + launchdLabel + ".plist", nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist"), nil
}

func systemctl(root bool, args ...string) (string, error) {
	if !root {
		args = append([]string{"--user"}, args...)
	}
	return runCmd("systemctl", args...)
}

// Install sets the service up and starts it.
func Install(s Service) (ServiceInfo, error) {
	switch runtime.GOOS {
	case "linux":
		p, err := systemdPath(s.Root)
		if err != nil {
			return ServiceInfo{}, err
		}
		if _, err := exec.LookPath("systemctl"); err != nil {
			return ServiceInfo{}, fmt.Errorf("this system has no systemd; start netcheck agent from your init system instead")
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return ServiceInfo{}, err
		}
		if err := os.WriteFile(p, []byte(SystemdUnit(s)), 0o644); err != nil {
			return ServiceInfo{}, err
		}
		if _, err := systemctl(s.Root, "daemon-reload"); err != nil {
			return ServiceInfo{}, err
		}
		if _, err := systemctl(s.Root, "enable", ServiceName); err != nil {
			return ServiceInfo{}, err
		}
		if _, err := systemctl(s.Root, "restart", ServiceName); err != nil {
			return ServiceInfo{}, err
		}
		info := ServiceState(s.Root)
		if !s.Root {
			// Without lingering, a user's services stop when they log out.
			if u := os.Getenv("USER"); u != "" {
				if _, err := runCmd("loginctl", "enable-linger", u); err != nil {
					info.Notes = append(info.Notes, "It runs only while you're logged in: run sudo loginctl enable-linger "+u+" to keep it running after you log out and start it at boot.")
				}
			}
		}
		return info, nil
	case "darwin":
		p, err := launchdPath(s.Root)
		if err != nil {
			return ServiceInfo{}, err
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return ServiceInfo{}, err
		}
		runCmd("launchctl", "unload", p)
		if err := os.WriteFile(p, []byte(LaunchdPlist(s)), 0o644); err != nil {
			return ServiceInfo{}, err
		}
		if _, err := runCmd("launchctl", "load", "-w", p); err != nil {
			return ServiceInfo{}, err
		}
		info := ServiceState(s.Root)
		if !s.Root {
			info.Notes = append(info.Notes, "It runs while you're logged in. For a server that nobody logs in to, install it with sudo (a LaunchDaemon).")
		}
		return info, nil
	case "windows":
		user := os.Getenv("USERDOMAIN") + `\` + os.Getenv("USERNAME")
		f, err := os.CreateTemp("", "netcheck-task-*.xml")
		if err != nil {
			return ServiceInfo{}, err
		}
		defer os.Remove(f.Name())
		f.Write(utf16File(TaskXML(s, user)))
		f.Close()
		if _, err := runCmd("schtasks", "/Create", "/TN", taskName, "/XML", f.Name(), "/F"); err != nil {
			return ServiceInfo{}, err
		}
		runCmd("schtasks", "/End", "/TN", taskName)
		waitStopped(s.PID)
		if _, err := runCmd("schtasks", "/Run", "/TN", taskName); err != nil {
			return ServiceInfo{}, err
		}
		info := ServiceState(false)
		info.Notes = append(info.Notes, "It starts when you sign in to Windows; a PC that should run it unattended needs to sign in automatically.")
		return info, nil
	}
	return ServiceInfo{}, fmt.Errorf("installing a service isn't supported on %s; start netcheck agent from your init system", runtime.GOOS)
}

// Uninstall stops the service and removes it; pidFile is the agent's.
func Uninstall(root bool, pidFile string) error {
	switch runtime.GOOS {
	case "linux":
		p, err := systemdPath(root)
		if err != nil {
			return err
		}
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("no agent service is installed (%s)", p)
		}
		systemctl(root, "disable", "--now", ServiceName)
		if err := os.Remove(p); err != nil {
			return err
		}
		systemctl(root, "daemon-reload")
		return nil
	case "darwin":
		p, err := launchdPath(root)
		if err != nil {
			return err
		}
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("no agent service is installed (%s)", p)
		}
		runCmd("launchctl", "unload", "-w", p)
		return os.Remove(p)
	case "windows":
		if !ServiceState(false).Installed {
			return fmt.Errorf("no agent task is installed")
		}
		runCmd("schtasks", "/End", "/TN", taskName)
		_, err := runCmd("schtasks", "/Delete", "/TN", taskName, "/F")
		waitStopped(pidFile)
		return err
	}
	return fmt.Errorf("not supported on %s", runtime.GOOS)
}

// waitStopped makes sure the agent in pidFile has stopped: schtasks /End
// returns before the agent is gone, and a new start would find the port
// taken. Only a netcheck process is stopped, never another that reused
// the pid.
func waitStopped(pidFile string) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pid := strings.TrimSpace(string(b))
	alive := func() bool {
		out, err := runCmd("tasklist", "/FI", "PID eq "+pid, "/FO", "CSV", "/NH")
		return err == nil && strings.Contains(strings.ToLower(out), `"netcheck.exe"`)
	}
	for i := 0; i < 10 && alive(); i++ {
		sleep(500 * time.Millisecond)
	}
	if alive() {
		runCmd("taskkill", "/PID", pid, "/F")
	}
}

// sleep is a test seam.
var sleep = time.Sleep

// ServiceState looks the service up.
func ServiceState(root bool) ServiceInfo {
	var info ServiceInfo
	switch runtime.GOOS {
	case "linux":
		p, _ := systemdPath(root)
		info.Where = p
		_, err := os.Stat(p)
		info.Installed = err == nil
		out, _ := systemctl(root, "is-active", ServiceName)
		info.Running = strings.TrimSpace(out) == "active"
		info.Logs = "journalctl --user -u " + ServiceName + " -f"
		if root {
			info.Logs = "journalctl -u " + ServiceName + " -f"
		}
	case "darwin":
		p, _ := launchdPath(root)
		info.Where = p
		_, err := os.Stat(p)
		info.Installed = err == nil
		out, err := runCmd("launchctl", "list", launchdLabel)
		info.Running = err == nil && strings.Contains(out, `"PID"`)
	case "windows":
		info.Where = `Task Scheduler: "` + taskName + `"`
		out, err := runCmd("schtasks", "/Query", "/TN", taskName, "/FO", "CSV", "/NH")
		info.Installed = err == nil
		info.Running = err == nil && taskRunning(out)
	}
	return info
}

// taskRunning reads schtasks /Query /FO CSV: "name","next run","status".
// The status is localized; "Running" in English.
func taskRunning(csv string) bool {
	f := strings.Split(strings.TrimSpace(csv), `","`)
	if len(f) < 3 {
		return false
	}
	st := strings.ToLower(strings.Trim(f[len(f)-1], `"`))
	for _, w := range []string{"running", "wird ausgeführt", "выполняется", "en cours", "en ejecución", "in esecuzione", "uitvoeren"} {
		if strings.Contains(st, w) {
			return true
		}
	}
	return false
}
