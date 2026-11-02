package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/tworjaga/netcheck/internal/ui"
)

// installDir is where `netcheck install` puts the binary: a per-user folder,
// so no administrator rights are needed. NETCHECK_INSTALL_DIR overrides it.
func installDir() (string, error) {
	if d := os.Getenv("NETCHECK_INSTALL_DIR"); d != "" {
		return d, nil
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			return "", errors.New("LOCALAPPDATA isn't set")
		}
		return filepath.Join(base, "Programs", "netcheck"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "bin"), nil
}

func binaryName() string {
	if runtime.GOOS == "windows" {
		return "netcheck.exe"
	}
	return "netcheck"
}

// samePath compares two paths the way the OS does (case-insensitively on
// Windows), ignoring trailing separators.
func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// pathHas reports whether a PATH-style list contains dir.
func pathHas(list, dir string) bool {
	for _, p := range filepath.SplitList(list) {
		if p != "" && samePath(p, dir) {
			return true
		}
	}
	return false
}

// pathAdd appends dir to a PATH-style list unless it's already there.
func pathAdd(list, dir string) string {
	if pathHas(list, dir) {
		return list
	}
	if list = strings.TrimRight(list, string(os.PathListSeparator)); list == "" {
		return dir
	}
	return list + string(os.PathListSeparator) + dir
}

// pathRemove drops every entry equal to dir from a PATH-style list.
func pathRemove(list, dir string) string {
	var keep []string
	for _, p := range filepath.SplitList(list) {
		if p != "" && !samePath(p, dir) {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, string(os.PathListSeparator))
}

// copyBinary puts src at dest via a temporary file. A binary that is running
// can't be overwritten on Windows but can be renamed, so an old copy moves
// aside to dest.old first (removed on the next install, if it no longer runs).
func copyBinary(src, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dest + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, asideName(dest)); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return os.Rename(tmp, dest)
}

// asideName clears out old copies moved aside before and picks a free
// name for this one. An old copy that still runs (the agent, say) can't be
// removed, so the next name is used instead.
func asideName(dest string) string {
	olds, _ := filepath.Glob(dest + ".old*")
	for _, o := range olds {
		_ = os.Remove(o)
	}
	name := dest + ".old"
	for i := 2; i < 100; i++ {
		if _, err := os.Stat(name); os.IsNotExist(err) {
			break
		}
		name = fmt.Sprintf("%s.old%d", dest, i)
	}
	return name
}

// stdinIsTTY is a test seam for "can we ask a question here".
var stdinIsTTY = ui.StdinTTY

// confirm asks a yes/no question on the terminal; the answer defaults to no.
var confirm = func(question string) bool {
	fmt.Print("  " + question + " [y/N] ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes"
}

type installReport struct {
	Binary    string `json:"binary"`
	Dir       string `json:"dir"`
	PathAdded bool   `json:"path_added"`
	OnPath    bool   `json:"on_path"`
	Error     string `json:"error,omitempty"`
}

func cmdInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	yes := fs.Bool("yes", false, "don't ask first")
	asJSON := fs.Bool("json", false, "machine-readable output (implies --yes)")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)
	fail := func(msg string) int {
		ui.Verdict(ui.Bad, msg)
		ui.Println("")
		if *asJSON {
			printJSON(installReport{Error: msg})
		}
		return 1
	}

	exe, err := os.Executable()
	if err != nil {
		return fail("Couldn't find this program's own file: " + err.Error())
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	dir, err := installDir()
	if err != nil {
		return fail("Couldn't work out where to install: " + err.Error())
	}
	dest := filepath.Join(dir, binaryName())
	cur, pathErr := userPath()
	onPath := pathErr == nil && pathHas(cur, dir)
	rep := installReport{Binary: dest, Dir: dir, OnPath: onPath}

	ui.Title("install")
	ui.Open("Install")
	if samePath(exe, dest) {
		ui.Println(ui.Row("Copy", ui.OK, "already installed", "", ui.Dim(dest)))
	} else {
		ui.Println(ui.Row("Copy", ui.OK, "to "+dir, "", ui.Dim("from "+exe)))
	}
	switch {
	case onPath:
		ui.Println(ui.Row("PATH", ui.OK, "already on PATH", "", ""))
	case setUserPath != nil:
		ui.Println(ui.Row("PATH", ui.OK, "add to your PATH", "", ui.Dim("user PATH, no admin rights")))
	default:
		ui.Println(ui.Row("PATH", ui.Warn, "not on PATH", "", ui.Dim("you add it to your shell profile")))
	}
	ui.Close()

	if !*yes && !*asJSON {
		if !stdinIsTTY() {
			ui.Println("\n  " + ui.Dim("Run netcheck install --yes to install without being asked.") + "\n")
			return 2
		}
		ui.Println("")
		if !confirm("Install netcheck?") {
			ui.Println("  " + ui.Dim("Nothing changed.") + "\n")
			return 0
		}
	}

	if !samePath(exe, dest) {
		if err := copyBinary(exe, dest); err != nil {
			return fail("Couldn't copy netcheck to " + dir + ": " + err.Error())
		}
	}
	var notes []string
	if !onPath && setUserPath != nil {
		if err := setUserPath(pathAdd(cur, dir)); err != nil {
			return fail("Copied, but couldn't add it to your PATH: " + err.Error())
		}
		rep.PathAdded, rep.OnPath = true, true
	}
	switch {
	case rep.OnPath && runtime.GOOS == "windows":
		notes = append(notes, "Open a new terminal from the Start menu, then run netcheck from any folder. Terminals already open, including tabs inside other apps, keep the old PATH until they're restarted.")
	case rep.OnPath:
		notes = append(notes, "Open a new terminal (open ones keep the old PATH), then run netcheck from any folder.")
	default:
		notes = append(notes, "Add this line to your shell profile (~/.profile, ~/.bashrc or ~/.zshrc), then open a new terminal:",
			`export PATH="`+dir+`:$PATH"`)
	}
	notes = append(notes, "netcheck uninstall removes it again.")
	ui.Verdict(ui.OK, "netcheck is installed in "+dir+".", notes...)
	ui.Println("")
	if *asJSON {
		printJSON(rep)
	}
	return 0
}

func cmdUninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	yes := fs.Bool("yes", false, "don't ask first")
	asJSON := fs.Bool("json", false, "machine-readable output (implies --yes)")
	parseInterspersed(fs, args)
	ui.SetQuiet(*asJSON)

	dir, err := installDir()
	if err != nil {
		ui.Verdict(ui.Bad, "Couldn't work out where netcheck is installed: "+err.Error())
		return 1
	}
	dest := filepath.Join(dir, binaryName())
	_, statErr := os.Stat(dest)
	installed := statErr == nil
	cur, pathErr := userPath()
	onPath := pathErr == nil && setUserPath != nil && pathHas(cur, dir)

	ui.Title("uninstall")
	if !installed && !onPath {
		ui.Verdict(ui.OK, "netcheck isn't installed in "+dir+"; nothing to remove.")
		ui.Println("")
		if *asJSON {
			printJSON(map[string]any{"removed": false, "dir": dir})
		}
		return 0
	}
	ui.Open("Uninstall")
	if installed {
		ui.Println(ui.Row("Remove", ui.OK, dest, "", ""))
	}
	if onPath {
		ui.Println(ui.Row("PATH", ui.OK, "remove from your PATH", "", ui.Dim(dir)))
	}
	ui.Close()
	if !*yes && !*asJSON {
		if !stdinIsTTY() {
			ui.Println("\n  " + ui.Dim("Run netcheck uninstall --yes to remove it without being asked.") + "\n")
			return 2
		}
		ui.Println("")
		if !confirm("Remove netcheck?") {
			ui.Println("  " + ui.Dim("Nothing changed.") + "\n")
			return 0
		}
	}

	var notes []string
	if onPath {
		if err := setUserPath(pathRemove(cur, dir)); err != nil {
			ui.Verdict(ui.Bad, "Couldn't remove it from your PATH: "+err.Error())
			return 1
		}
	}
	if installed {
		if err := os.Remove(dest); err != nil {
			// Windows can't delete a program while it runs, but can rename it.
			if err := os.Rename(dest, dest+".old"); err != nil {
				ui.Verdict(ui.Bad, "Couldn't remove "+dest+": "+err.Error())
				return 1
			}
			notes = append(notes, "This copy is running, so it was renamed to netcheck.exe.old; delete it once this window is closed.")
		}
		_ = os.Remove(dest + ".old")
		if runtime.GOOS == "windows" {
			_ = os.Remove(dir) // only succeeds when the folder is empty
		}
	}
	ui.Verdict(ui.OK, "netcheck is uninstalled.", notes...)
	ui.Println("")
	if *asJSON {
		out, _ := json.Marshal(map[string]any{"removed": true, "dir": dir})
		fmt.Println(string(out))
	}
	return 0
}
