package adv

import (
	"encoding/json"
	"io"
	"time"
)

// Finding is one conclusion: a status ("ok", "warn", "bad", "skip") and a
// sentence.
type Finding struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// Envelope is the --json shape every Advanced tool prints: what was
// checked, the verdict, the findings behind it, the tool's own data, and
// the --fail-on rules that broke.
type Envelope struct {
	Tool     string    `json:"tool"`
	Version  string    `json:"netcheck_version"`
	Time     time.Time `json:"time"`
	Targets  []Target  `json:"targets,omitempty"`
	Verdict  Finding   `json:"verdict"`
	Findings []Finding `json:"findings"`
	Data     any       `json:"data,omitempty"`
	FailedOn []string  `json:"failed_on,omitempty"`
}

// Write prints the envelope as indented JSON.
func (e Envelope) Write(w io.Writer) error {
	if e.Findings == nil {
		e.Findings = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(e)
}
