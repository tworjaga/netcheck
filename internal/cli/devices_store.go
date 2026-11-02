package cli

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
)

// knownDevice is one device netcheck has seen on a network before.
type knownDevice struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"mac,omitempty"`
	Name      string    `json:"name,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// knownNetwork is what netcheck remembers about one network.
type knownNetwork struct {
	Subnet   string                  `json:"subnet"`
	LastScan time.Time               `json:"last_scan"`
	Devices  map[string]*knownDevice `json:"devices"` // by deviceKey
}

// deviceStore is the devices file: the devices seen on each network, so the
// next scan can say which ones are new.
type deviceStore struct {
	V        int                      `json:"v"`
	Networks map[string]*knownNetwork `json:"networks"` // by networkKey
}

// forgetAfter drops devices that haven't been seen for this long.
const forgetAfter = 90 * 24 * time.Hour

// devicesPath is os.UserConfigDir()/netcheck/devices.json, overridable with
// NETCHECK_DEVICES.
func devicesPath() (string, error) {
	if p := os.Getenv("NETCHECK_DEVICES"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netcheck", "devices.json"), nil
}

// loadDevices reads the devices file; a missing file is an empty store.
func loadDevices(path string) (*deviceStore, error) {
	s := &deviceStore{V: 1, Networks: map[string]*knownNetwork{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return &deviceStore{V: 1, Networks: map[string]*knownNetwork{}}, err
	}
	if s.Networks == nil {
		s.Networks = map[string]*knownNetwork{}
	}
	return s, nil
}

// save writes the store atomically (temp file, then rename).
func (s *deviceStore) save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// networkKey identifies a network by its router's MAC address, so home and
// school Wi-Fi with the same 192.168.0.0/24 aren't mixed up. Without one it
// falls back to the subnet.
func networkKey(devs []probe.Device, subnet string) string {
	for _, d := range devs {
		if d.Gateway && d.MAC != "" {
			return "router " + d.MAC
		}
	}
	return "subnet " + subnet
}

// deviceKey identifies a device by MAC, or by address when there's no MAC.
func deviceKey(d probe.Device) string {
	if d.MAC != "" {
		return d.MAC
	}
	return "ip " + d.IP
}

// deviceDiff is what a scan found compared with the last one.
type deviceDiff struct {
	First bool      // nothing remembered for this network yet
	Since time.Time // the previous scan
	New   map[string]bool
}

// remember compares a scan with what's known about the network, then
// records the scan: new devices are added, seen ones refreshed, and ones
// unseen for forgetAfter dropped.
func (s *deviceStore) remember(key, subnet string, devs []probe.Device, now time.Time) deviceDiff {
	n := s.Networks[key]
	diff := deviceDiff{New: map[string]bool{}}
	if n == nil {
		n = &knownNetwork{Devices: map[string]*knownDevice{}}
		s.Networks[key] = n
		diff.First = true
	} else {
		diff.Since = n.LastScan
	}
	if n.Devices == nil {
		n.Devices = map[string]*knownDevice{}
	}
	for _, d := range devs {
		k := deviceKey(d)
		kd := n.Devices[k]
		if kd == nil {
			kd = &knownDevice{FirstSeen: now}
			n.Devices[k] = kd
			if !diff.First {
				diff.New[k] = true
			}
		}
		kd.IP, kd.MAC, kd.LastSeen = d.IP, d.MAC, now
		if d.Name != "" {
			kd.Name = d.Name
		}
	}
	for k, kd := range n.Devices {
		if now.Sub(kd.LastSeen) > forgetAfter {
			delete(n.Devices, k)
		}
	}
	n.Subnet, n.LastScan = subnet, now
	return diff
}
