package probe

import (
	"context"
	"math"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// WifiNet is one access point seen in a scan.
type WifiNet struct {
	SSID      string `json:"ssid"`
	BSSID     string `json:"bssid,omitempty"`
	Channel   int    `json:"channel"`
	Band      string `json:"band,omitempty"`
	SignalDBm int    `json:"signal_dbm,omitempty"` // 0 = unknown
	SignalPct int    `json:"signal_pct,omitempty"`
}

// WifiInfo describes the current Wi-Fi link and the airwaves around it.
type WifiInfo struct {
	Available bool      `json:"available"` // a Wi-Fi adapter was found
	Connected bool      `json:"connected"`
	Interface string    `json:"interface,omitempty"`
	SSID      string    `json:"ssid,omitempty"`
	BSSID     string    `json:"bssid,omitempty"`
	Band      string    `json:"band,omitempty"`
	Channel   int       `json:"channel,omitempty"`
	Radio     string    `json:"radio,omitempty"`
	SignalPct int       `json:"signal_pct,omitempty"`
	SignalDBm int       `json:"signal_dbm,omitempty"`
	RateMbps  float64   `json:"rate_mbps,omitempty"`
	Security  string    `json:"security,omitempty"` // as the system says it: "WPA2-Personal", "WPA3", "Open"...
	Cipher    string    `json:"cipher,omitempty"`   // "CCMP", "TKIP", "GCMP"...
	Neighbors []WifiNet `json:"neighbors,omitempty"`
	Sharing   int       `json:"networks_on_channel"` // strong networks overlapping our channel
	Crowding  string    `json:"crowding,omitempty"`  // quiet, moderate, crowded, or "" if unknown
	BestChan  int       `json:"better_channel,omitempty"`
	Note      string    `json:"note,omitempty"` // one dim line: permission, scan limits
	Error     string    `json:"error,omitempty"`
}

// ---- helpers shared by the parsers ----

func pctToDBm(p int) int { return p/2 - 100 }
func dbmToPct(d int) int { return max(0, min(100, 2*(d+100))) }

// freqToChannel converts MHz to a Wi-Fi channel number and band.
func freqToChannel(mhz int) (int, string) {
	switch {
	case mhz == 2484:
		return 14, "2.4 GHz"
	case mhz >= 2412 && mhz <= 2472:
		return (mhz - 2407) / 5, "2.4 GHz"
	case mhz >= 5170 && mhz <= 5895:
		return (mhz - 5000) / 5, "5 GHz"
	case mhz >= 5955 && mhz <= 7115:
		return (mhz - 5950) / 5, "6 GHz"
	}
	return 0, ""
}

func bandFromChannel(ch int) string {
	switch {
	case ch >= 1 && ch <= 14:
		return "2.4 GHz"
	case ch >= 32:
		return "5 GHz"
	}
	return ""
}

func kv(line string) (key, val string, ok bool) {
	i := strings.Index(line, ":")
	if i < 0 {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(line[:i])), strings.TrimSpace(line[i+1:]), true
}

func atoi(s string) int {
	f := strings.Fields(strings.NewReplacer("%", " ", "MHz", " ").Replace(s))
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(f[0])
	return n
}

func atof(s string) float64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(strings.ReplaceAll(f[0], ",", "."), 64)
	return v
}

// netshKey normalizes a netsh key for matching. netsh prints in the
// console's OEM code page (CP850, CP852, …), not UTF-8, so a localized key
// such as "Señal" arrives as invalid UTF-8. Every non-ASCII character becomes
// a single "?" whichever encoding it came in, and the patterns below use "?"
// where the localized word has an accented letter.
func netshKey(key string) string {
	var b strings.Builder
	for _, r := range key {
		if r > 127 {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isKey reports whether key equals one of words exactly.
func isKey(key string, words ...string) bool {
	k := netshKey(key)
	for _, w := range words {
		if k == w {
			return true
		}
	}
	return false
}

// Localized Windows key names (netsh output follows the display language).
// Channel and signal match exactly: the networks list also has keys like
// "Channel Utilization" that a prefix match would mistake for the channel.
var (
	kName    = []string{"name", "nom", "nombre", "nome", "naam", "nazwa"}
	kChannel = []string{"channel", "kanal", "canal", "canale", "kanaal", "kana?"}
	kSignal  = []string{"signal", "se?al", "segnale", "sygna?", "sinal"}
	kBand    = []string{"band", "bande", "banda", "frequentieband", "pasmo"}
	kRadio   = []string{"radio type", "funktyp", "type de radio", "tipo de radio", "tipo di radio", "radiotype", "typ radia"}
	kAuth    = []string{"authentication", "authentifizierung", "authentification", "autenticaci", "autenticazione", "verificatie", "uwierzytelnianie", "autentica"}
	kCipher  = []string{"cipher", "verschl", "chiffrement", "cifrado", "crittografia", "codering", "szyfr", "codifica"}
	kRate    = []string{"receive rate", "empfangsrate", "vitesse de r?ception", "velocidad de recepci?n", "velocit? di ricezione", "ontvangstsnelheid", "taxa de recep??o", "szybko?? odbierania"}
)

// hasAny reports whether the normalized key starts with one of prefixes.
func hasAny(key string, prefixes ...string) bool {
	k := netshKey(key)
	for _, p := range prefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// normBand maps "5 GHz", "2,4 GHz" (German, French) and similar onto the
// band names the analysis uses.
func normBand(v string) string {
	v = strings.ReplaceAll(strings.TrimSpace(v), ",", ".")
	switch {
	case strings.HasPrefix(v, "2.4"):
		return "2.4 GHz"
	case strings.HasPrefix(v, "5"):
		return "5 GHz"
	case strings.HasPrefix(v, "6"):
		return "6 GHz"
	}
	return v
}

var locationHint = regexp.MustCompile(`(?i)location|standort|localisation|ubicaci|posizione|locatie`)

// ---- Windows: netsh wlan ----

func parseNetshInterfaces(out string) WifiInfo {
	info := WifiInfo{}
	for _, ln := range strings.Split(out, "\n") {
		key, val, ok := kv(ln)
		if !ok {
			continue
		}
		switch {
		case isKey(key, kName...) && info.Interface == "":
			info.Interface = val
			info.Available = true
		case key == "guid":
			info.Available = true
		case key == "ssid":
			info.SSID = val
		case key == "rssi":
			// Windows 11 prints the real RSSI; better than converting Signal %.
			info.SignalDBm = atoi(val)
		case key == "bssid" || key == "ap bssid" || key == "ap-bssid":
			// Windows 11 says "AP BSSID"; older builds say "BSSID".
			info.BSSID = strings.ToLower(val)
		case isKey(key, kChannel...):
			info.Channel = atoi(val)
		case isKey(key, kSignal...) || (info.SignalPct == 0 && strings.HasSuffix(val, "%")):
			// Signal is the only percentage in this output, which also
			// catches languages whose key isn't listed above.
			info.SignalPct = atoi(val)
		case isKey(key, kBand...) || strings.HasSuffix(val, "GHz"):
			info.Band = normBand(val)
		case hasAny(key, kRadio...):
			info.Radio = val
		case hasAny(key, kRate...):
			info.RateMbps = atof(val)
		case hasAny(key, kAuth...):
			info.Security = val
		case hasAny(key, kCipher...):
			info.Cipher = val
		}
	}
	info.Connected = info.SSID != ""
	if info.Connected {
		if info.SignalDBm == 0 {
			info.SignalDBm = pctToDBm(info.SignalPct)
		}
		if info.Band == "" {
			info.Band = bandFromChannel(info.Channel)
		}
	}
	return info
}

func parseNetshNetworks(out string) []WifiNet {
	var nets []WifiNet
	ssid := ""
	var cur *WifiNet
	flush := func() {
		if cur != nil {
			if cur.Band == "" {
				cur.Band = bandFromChannel(cur.Channel)
			}
			cur.SignalDBm = pctToDBm(cur.SignalPct)
			nets = append(nets, *cur)
			cur = nil
		}
	}
	for _, ln := range strings.Split(out, "\n") {
		key, val, ok := kv(ln)
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(key, "ssid "):
			flush()
			ssid = val
		case strings.HasPrefix(key, "bssid "):
			flush()
			cur = &WifiNet{SSID: ssid, BSSID: strings.ToLower(val)}
		case cur != nil && isKey(key, kChannel...):
			cur.Channel = atoi(val)
		case cur != nil && (isKey(key, kSignal...) || strings.HasSuffix(val, "%") && !strings.Contains(val, "(")):
			cur.SignalPct = atoi(val)
		case cur != nil && (isKey(key, kBand...) || strings.HasSuffix(val, "GHz")):
			cur.Band = normBand(val)
		}
	}
	flush()
	return nets
}

func readWindows(ctx context.Context) WifiInfo {
	out, err := Run(ctx, 8*time.Second, "netsh", "wlan", "show", "interfaces")
	info := parseNetshInterfaces(out)
	if err != nil && !info.Available {
		low := strings.ToLower(out)
		if strings.Contains(low, "wlan autoconfig service") || strings.Contains(low, "not running") {
			return WifiInfo{Note: "the Windows WLAN service isn't running, so there's no Wi-Fi adapter to read"}
		}
		return WifiInfo{}
	}
	if !info.Connected {
		if locationHint.MatchString(out) {
			info.Note = "Windows hides Wi-Fi details until Location is on (Settings → Privacy & security → Location)"
		}
		return info
	}
	nout, _ := Run(ctx, 10*time.Second, "netsh", "wlan", "show", "networks", "mode=bssid")
	if locationHint.MatchString(nout) && !strings.Contains(strings.ToUpper(nout), "BSSID") {
		info.Note = "Windows needs Location turned on to list nearby networks, so channel crowding is unknown"
		return info
	}
	info.Neighbors = parseNetshNetworks(nout)
	return info
}

// ---- Linux: nmcli, then iw ----

// splitTerse splits nmcli -t output on unescaped colons.
func splitTerse(line string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '\\' && i+1 < len(line):
			cur.WriteByte(line[i+1])
			i++
		case line[i] == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(line[i])
		}
	}
	return append(out, cur.String())
}

// parseNmcli reads `nmcli -t -f ACTIVE,SSID,BSSID,CHAN,FREQ,SIGNAL,RATE[,SECURITY]`.
func parseNmcli(out string) WifiInfo {
	info := WifiInfo{}
	for _, ln := range strings.Split(out, "\n") {
		f := splitTerse(strings.TrimSpace(ln))
		if len(f) < 7 {
			continue
		}
		info.Available = true
		pct := atoi(f[5])
		ch, band := freqToChannel(atoi(f[4]))
		if c := atoi(f[3]); c > 0 {
			ch = c
		}
		if band == "" {
			band = bandFromChannel(ch)
		}
		n := WifiNet{SSID: f[1], BSSID: strings.ToLower(f[2]), Channel: ch, Band: band, SignalPct: pct, SignalDBm: pctToDBm(pct)}
		if f[0] == "yes" {
			info.Connected = true
			info.SSID, info.BSSID, info.Channel, info.Band = n.SSID, n.BSSID, ch, band
			info.SignalPct, info.SignalDBm = pct, n.SignalDBm
			info.RateMbps = atof(f[6])
			if len(f) > 7 {
				info.Security = strings.TrimSpace(f[7])
				if info.Security == "" || info.Security == "--" {
					info.Security = "Open"
				}
			}
			continue
		}
		info.Neighbors = append(info.Neighbors, n)
	}
	return info
}

var ifaceRe = regexp.MustCompile(`(?m)^\s*Interface\s+(\S+)`)
var iwBSSIDRe = regexp.MustCompile(`(?i)connected to ([0-9a-f:]{17})`)

func parseIwLink(out string) WifiInfo {
	info := WifiInfo{Available: true}
	if strings.Contains(out, "Not connected") {
		return info
	}
	for _, ln := range strings.Split(out, "\n") {
		key, val, ok := kv(ln)
		if !ok {
			continue
		}
		switch key {
		case "ssid":
			info.SSID = val
			info.Connected = true
		case "freq":
			info.Channel, info.Band = freqToChannel(atoi(val))
		case "signal":
			info.SignalDBm = int(math.Round(atof(val)))
			info.SignalPct = dbmToPct(info.SignalDBm)
		case "rx bitrate":
			info.RateMbps = atof(val)
		}
	}
	if m := iwBSSIDRe.FindStringSubmatch(out); m != nil {
		info.BSSID = strings.ToLower(m[1])
	}
	return info
}

func readLinux(ctx context.Context) WifiInfo {
	if out, err := Run(ctx, 12*time.Second, "nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,FREQ,SIGNAL,RATE,SECURITY", "dev", "wifi", "list"); err == nil {
		if info := parseNmcli(out); info.Available {
			return info
		}
	}
	devs, err := Run(ctx, 4*time.Second, "iw", "dev")
	if err != nil {
		return WifiInfo{}
	}
	m := ifaceRe.FindStringSubmatch(devs)
	if m == nil {
		return WifiInfo{}
	}
	out, _ := Run(ctx, 4*time.Second, "iw", "dev", m[1], "link")
	info := parseIwLink(out)
	info.Interface = m[1]
	info.Note = "channel crowding needs nmcli, or root for iw scans"
	return info
}

// ---- macOS: system_profiler ----

func indent(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }

// parseSystemProfiler reads `system_profiler SPAirPortDataType`. Sections are
// found by indentation: an SSID heading sits two spaces under its section.
func parseSystemProfiler(out string) WifiInfo {
	info := WifiInfo{}
	section, secIndent := "", -1
	var cur *WifiNet
	flush := func() {
		if cur != nil && section == "other" {
			info.Neighbors = append(info.Neighbors, *cur)
		}
		cur = nil
	}
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" {
			continue
		}
		ind := indent(ln)
		if section != "" && ind <= secIndent { // left the section
			flush()
			section = ""
		}
		switch {
		case strings.HasPrefix(t, "Current Network Information:"):
			section, secIndent, info.Available, info.Connected = "current", ind, true, true
			continue
		case strings.HasPrefix(t, "Other Local Wi-Fi Networks:"):
			section, secIndent, info.Available = "other", ind, true
			continue
		}
		if section == "" {
			if info.Interface == "" && strings.HasSuffix(t, ":") && strings.HasPrefix(t, "en") {
				info.Interface = strings.TrimSuffix(t, ":")
			}
			continue
		}
		if ind == secIndent+2 && strings.HasSuffix(t, ":") { // SSID heading
			flush()
			cur = &WifiNet{SSID: strings.TrimSuffix(t, ":")}
			continue
		}
		key, val, ok := kv(t)
		if cur == nil || !ok {
			continue
		}
		switch key {
		case "channel":
			fields := strings.Fields(strings.NewReplacer("(", " ", ")", " ", ",", " ").Replace(val))
			if len(fields) > 0 {
				cur.Channel, _ = strconv.Atoi(fields[0])
			}
			for _, f := range fields[min(1, len(fields)):] {
				switch strings.ToLower(f) {
				case "2ghz":
					cur.Band = "2.4 GHz"
				case "5ghz":
					cur.Band = "5 GHz"
				case "6ghz":
					cur.Band = "6 GHz"
				}
			}
		case "signal / noise":
			if f := strings.Fields(val); len(f) > 0 {
				cur.SignalDBm, _ = strconv.Atoi(f[0])
				cur.SignalPct = dbmToPct(cur.SignalDBm)
			}
		case "phy mode":
			if section == "current" {
				info.Radio = val
			}
		case "transmit rate":
			if section == "current" {
				info.RateMbps = atof(val)
			}
		case "security":
			if section == "current" {
				info.Security = val
			}
		}
		if section == "current" {
			info.SSID, info.Channel, info.Band = cur.SSID, cur.Channel, cur.Band
			info.SignalDBm, info.SignalPct = cur.SignalDBm, cur.SignalPct
		}
	}
	flush()
	if info.SSID == "<redacted>" {
		info.SSID = ""
		info.Note = "macOS hides the network name without Location access; signal and channel are still shown"
	}
	return info
}

func readDarwin(ctx context.Context) WifiInfo {
	out, err := Run(ctx, 20*time.Second, "system_profiler", "SPAirPortDataType")
	if err != nil && out == "" {
		return WifiInfo{}
	}
	return parseSystemProfiler(out)
}

// ---- analysis ----

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// overlaps reports whether a neighbor on channel nb interferes with own.
func overlaps(band string, own, nb int) bool {
	if band == "2.4 GHz" {
		return abs(own-nb) <= 4
	}
	return own == nb
}

func strongEnough(n WifiNet) bool {
	if n.SignalDBm != 0 {
		return n.SignalDBm >= -82
	}
	return n.SignalPct >= 18
}

// loadOn counts strong neighbors that would overlap channel ch.
func loadOn(info WifiInfo, ch int) int {
	n := 0
	for _, nb := range info.Neighbors {
		if nb.Band != info.Band && nb.Band != "" && info.Band != "" {
			continue
		}
		if info.BSSID != "" && nb.BSSID == info.BSSID {
			continue
		}
		if strongEnough(nb) && overlaps(info.Band, ch, nb.Channel) {
			n++
		}
	}
	return n
}

// Analyze fills in channel crowding and a better-channel suggestion.
func (w *WifiInfo) Analyze() {
	// The scan lists the access point we're connected to as well; it isn't a
	// neighbour, so it leaves the list (and the JSON).
	if w.BSSID != "" {
		kept := w.Neighbors[:0]
		for _, n := range w.Neighbors {
			if n.BSSID != w.BSSID {
				kept = append(kept, n)
			}
		}
		w.Neighbors = kept
	}
	if !w.Connected || w.Channel == 0 || len(w.Neighbors) == 0 {
		return
	}
	n := loadOn(*w, w.Channel)
	w.Sharing = n
	quiet, moderate := 2, 5
	if w.Band != "2.4 GHz" {
		quiet, moderate = 1, 3
	}
	switch {
	case n <= quiet:
		w.Crowding = "quiet"
	case n <= moderate:
		w.Crowding = "moderate"
	default:
		w.Crowding = "crowded"
	}
	var cands []int
	switch w.Band {
	case "2.4 GHz":
		cands = []int{1, 6, 11}
	case "5 GHz":
		cands = []int{36, 40, 44, 48, 149, 153, 157, 161}
	}
	sort.Ints(cands)
	best, bestLoad := 0, n
	for _, c := range cands {
		if l := loadOn(*w, c); l < bestLoad {
			best, bestLoad = c, l
		}
	}
	if best != 0 && n-bestLoad >= 2 {
		w.BestChan = best
	}
}

// SignalQuality turns a dBm reading into a plain-English word.
func SignalQuality(dbm int) string {
	switch {
	case dbm == 0:
		return "unknown"
	case dbm >= -60:
		return "excellent"
	case dbm >= -67:
		return "good"
	case dbm >= -75:
		return "fair"
	case dbm >= -82:
		return "weak"
	}
	return "very weak"
}

// ReadWifi reads the current Wi-Fi link using the platform's own tools. It
// needs no elevation; anything it can't see is explained in Note.
func ReadWifi(ctx context.Context) WifiInfo {
	var info WifiInfo
	switch runtime.GOOS {
	case "windows":
		info = readWindows(ctx)
	case "linux":
		info = readLinux(ctx)
	case "darwin":
		info = readDarwin(ctx)
	default:
		return WifiInfo{Error: "Wi-Fi details aren't supported on " + runtime.GOOS}
	}
	info.Analyze()
	return info
}

// SampleSignal reads the current signal (dBm) every interval until ctx ends
// or n samples are taken (0 = until ctx ends). Failed reads are reported as 0.
func SampleSignal(ctx context.Context, interval time.Duration, n int, read func(context.Context) WifiInfo, onSample func(dbm int)) []int {
	var out []int
	for i := 0; (n == 0 || i < n) && ctx.Err() == nil; i++ {
		info := read(ctx)
		d := 0
		if info.Connected {
			d = info.SignalDBm
		}
		out = append(out, d)
		if onSample != nil {
			onSample(d)
		}
		select {
		case <-ctx.Done():
		case <-time.After(interval):
		}
	}
	return out
}
