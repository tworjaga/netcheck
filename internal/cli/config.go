package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// appConfig is netcheck's small settings file. Everything in it is a
// convenience; a missing or unreadable file means the defaults.
type appConfig struct {
	MenuMode string `json:"menu_mode,omitempty"` // "normal" or "advanced"
}

// configPath is os.UserConfigDir()/netcheck/config.json, overridable with
// NETCHECK_CONFIG.
func configPath() (string, error) {
	if p := os.Getenv("NETCHECK_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netcheck", "config.json"), nil
}

func loadConfig() appConfig {
	var c appConfig
	if p, err := configPath(); err == nil {
		if b, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(b, &c)
		}
	}
	return c
}

// saveConfig writes the settings atomically; failing only loses them.
func saveConfig(c appConfig) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(p+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}
