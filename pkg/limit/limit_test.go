package limit

import "testing"

func TestConnectionsPerIP(t *testing.T) {
	c := &Connections{MaxPerIP: 2}
	for i := 0; i < 2; i++ {
		if !c.Acquire("a") {
			t.Fatalf("expected connection %d from a to be accepted", i+1)
		}
	}
	if c.Acquire("a") {
		t.Fatal("expected third connection from a to be rejected")
	}
	if !c.Acquire("b") {
		t.Fatal("expected connection from b to be accepted")
	}
	c.Release("a")
	if !c.Acquire("a") {
		t.Fatal("expected connection from a to be accepted after release")
	}
}

func TestConnectionsTotal(t *testing.T) {
	c := &Connections{Max: 2}
	if !c.Acquire("a") || !c.Acquire("b") {
		t.Fatal("expected first two connections to be accepted")
	}
	if c.Acquire("c") {
		t.Fatal("expected third connection to be rejected")
	}
	c.Release("b")
	if !c.Acquire("c") {
		t.Fatal("expected connection to be accepted after release")
	}
	c.Release("a")
	c.Release("c")
	if len(c.perIP) != 0 || c.total != 0 {
		t.Fatalf("expected no tracked connections, got total=%d perIP=%v", c.total, c.perIP)
	}
}

func TestConnectionsUnlimited(t *testing.T) {
	c := &Connections{}
	for i := 0; i < 1000; i++ {
		if !c.Acquire("a") {
			t.Fatal("expected unlimited connections to be accepted")
		}
	}
}
