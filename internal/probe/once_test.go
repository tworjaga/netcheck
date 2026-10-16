package probe

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPingerPrefersICMP(t *testing.T) {
	withEchoer(t, &fakeEcho{script: []float64{7, -1, 9}}, nil)
	p, err := NewPinger(context.Background(), "127.0.0.1", []int{1})
	if err != nil || p.Method != "icmp" {
		t.Fatalf("got %+v, %v", p, err)
	}
	// icmpAnswers used the first reply; the script continues from there.
	if a, b := p.Once(context.Background(), time.Second), p.Once(context.Background(), time.Second); a != -1 || b != 9 {
		t.Fatalf("want -1 then 9 ms, got %v, %v", a, b)
	}
}

func TestPingerFallsBackToTCP(t *testing.T) {
	withEchoer(t, nil, ErrNoICMP)
	port, stop := freeTCP(t)
	defer stop()
	p, err := NewPinger(context.Background(), "127.0.0.1", []int{port})
	if err != nil || p.Method == "icmp" {
		t.Fatalf("got %+v, %v", p, err)
	}
	if p.Once(context.Background(), time.Second) < 0 {
		t.Fatal("open port should answer")
	}
}

func TestPingerNothingAnswersStillUsable(t *testing.T) {
	withEchoer(t, &fakeEcho{script: []float64{-1}}, nil)
	p, err := NewPinger(context.Background(), "127.0.0.1", nil)
	if !errors.Is(err, ErrNoReply) || p == nil || p.Method != "icmp" {
		t.Fatalf("got %+v, %v", p, err)
	}
	if p.Once(context.Background(), time.Millisecond) != -1 {
		t.Fatal("lost probe should be -1")
	}
}

func TestLookupOnce(t *testing.T) {
	port, stop := fakeDNS(t, false)
	r := Resolver{Addr: "127.0.0.1", Port: port}
	if LookupOnce(context.Background(), r, "example.com.", time.Second) < 0 {
		t.Fatal("answer expected")
	}
	if LookupOnce(context.Background(), r, "nxabc.com.", time.Second) < 0 {
		t.Fatal("NXDOMAIN is still an answer")
	}
	stop()
	time.Sleep(20 * time.Millisecond)
	if LookupOnce(context.Background(), r, "example.com.", 300*time.Millisecond) != -1 {
		t.Fatal("dead server should be -1")
	}
}
