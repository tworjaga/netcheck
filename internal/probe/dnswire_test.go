package probe

import (
	"net"
	"testing"
)

func TestBuildAndParseQuery(t *testing.T) {
	q := BuildQuery(0xBEEF, "example.com.", TypeA, true, true)
	m, err := ParseMsg(q)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 0xBEEF || m.Response || len(m.Questions) != 1 || m.Questions[0] != "example.com." {
		t.Fatalf("got %+v", m)
	}
}

func TestParseAnswersWithCompression(t *testing.T) {
	b := []byte{0x12, 0x34, 0x81, 0xA0, 0, 1, 0, 2, 0, 0, 0, 0}
	b = appendName(b, "host.local.")
	b = append(b, 0, TypeA, 0, 1)
	b = append(b, 0xC0, 12, 0, TypeA, 0, 1, 0, 0, 0, 60, 0, 4, 192, 168, 1, 9)
	b = append(b, 0xC0, 12, 0, TypeTXT, 0, 1, 0, 0, 0, 60, 0, 6, 5, 'h', 'e', 'l', 'l', 'o')
	m, err := ParseMsg(b)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Response || !m.AD || m.RCode != 0 {
		t.Fatalf("flags: %+v", m)
	}
	if len(m.Answers) != 2 || !m.Answers[0].IP.Equal(net.IPv4(192, 168, 1, 9)) || m.Answers[0].Name != "host.local." {
		t.Fatalf("A answer: %+v", m.Answers)
	}
	if len(m.Answers[1].Text) != 1 || m.Answers[1].Text[0] != "hello" {
		t.Fatalf("TXT answer: %+v", m.Answers[1])
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := ParseMsg([]byte{1, 2, 3}); err == nil {
		t.Fatal("short message should fail")
	}
	b := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1} // pointer loop
	if _, err := ParseMsg(b); err == nil {
		t.Fatal("pointer loop should fail")
	}
}

func TestReverseName(t *testing.T) {
	if got := ReverseName(net.IPv4(8, 8, 4, 100)); got != "100.4.8.8.in-addr.arpa." {
		t.Fatal(got)
	}
}
