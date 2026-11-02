package cli

import (
	"strings"
	"testing"

	"github.com/tworjaga/netcheck/internal/domain"
	"github.com/tworjaga/netcheck/internal/lanaudit"
	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

func TestLanDeviceTable(t *testing.T) {
	r := lanaudit.Report{
		Devices: []lanaudit.DeviceReport{
			{Device: probe.Device{IP: "192.168.0.1", Gateway: true}, Open: []lanaudit.Open{{Port: 80, Name: "web page (HTTP)"}}, Known: true},
			{Device: probe.Device{IP: "192.168.0.20", Name: "a-very-long-device-name.local", MAC: "aa:bb:cc:dd:ee:ff"}, Open: []lanaudit.Open{{Port: 445, Name: "file sharing (SMB)"}, {Port: 6379, Name: "Redis"}, {Port: 22, Name: "SSH"}}},
			{Device: probe.Device{IP: "192.168.0.200", Self: true}},
		},
		Checks: []domain.Check{{Area: lanaudit.AreaDevices, Status: domain.Bad, Title: "192.168.0.20 (nas): Redis"}},
	}
	tb := lanDeviceTable(r, 78)
	if tb.Rows[1].Status != ui.Bad || tb.Rows[0].Status != ui.OK || !strings.Contains(tb.Rows[0].Cells[1], "router") {
		t.Errorf("rows: %+v", tb.Rows)
	}
	if !strings.Contains(tb.Rows[1].Cells[1], "new") || strings.Contains(tb.Rows[0].Cells[1], "new") {
		t.Errorf("new marks: %+v", tb.Rows)
	}
	for _, l := range tb.Lines(78) {
		if ui.VisWidth(l) > 78 {
			t.Errorf("too wide: %q", l)
		}
	}
}
