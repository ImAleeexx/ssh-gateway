package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.htdvisser.nl/ssh-gateway/pkg/log"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestUserRegexp(t *testing.T) {
	for _, user := range []string{"target", "web-1", "db.internal", "a..b", "0"} {
		if !userRegexp.MatchString(user) {
			t.Errorf("expected %q to be accepted", user)
		}
	}
	for _, user := range []string{"", ".", "..", ".hidden", "../server", "a/b", `a\b`, "Target", "-x"} {
		if userRegexp.MatchString(user) {
			t.Errorf("expected %q to be rejected", user)
		}
	}
}

func newPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestAppendKnownHostKeepsAllHosts(t *testing.T) {
	gtw := &Gateway{}
	file := filepath.Join(t.TempDir(), "known_host_generated")
	jumpAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 22}
	upstreamAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 22}
	jumpKey, upstreamKey := newPublicKey(t), newPublicKey(t)

	if err := gtw.appendKnownHost(file, "jump:22", jumpAddr, jumpKey); err != nil {
		t.Fatal(err)
	}
	if err := gtw.appendKnownHost(file, "upstream:22", upstreamAddr, upstreamKey); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("expected owner-only permissions, got %v", perm)
	}

	callback, err := knownhosts.New(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("jump:22", jumpAddr, jumpKey); err != nil {
		t.Errorf("expected jump host key to be known, got %v", err)
	}
	if err := callback("upstream:22", upstreamAddr, upstreamKey); err != nil {
		t.Errorf("expected upstream host key to be known, got %v", err)
	}
	if err := callback("upstream:22", upstreamAddr, jumpKey); err == nil {
		t.Error("expected mismatching upstream host key to be rejected")
	}
}

func newTestGateway(t *testing.T) *Gateway {
	t.Helper()
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "server"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "upstreams"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "server", "ssh_host_ed25519_key"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := log.NewContext(context.Background(), zap.NewNop())
	gtw := NewGateway(ctx, dataDir)
	if err := gtw.LoadConfig(); err != nil {
		t.Fatal(err)
	}
	return gtw
}

func TestHandshakeTimeout(t *testing.T) {
	gtw := newTestGateway(t)
	gtw.SetHandshakeTimeout(200 * time.Millisecond)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	done := make(chan struct{})
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		gtw.Handle(conn)
		close(done)
	}()

	// Connect, but never send anything.
	client, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("expected idle connection to be closed after the handshake timeout")
	}
}

func writeDSAKey(t *testing.T, dataDir string) {
	t.Helper()
	// The key contents do not matter: the PEM block type is rejected first.
	block := &pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte{0x30, 0x00}}
	if err := os.WriteFile(filepath.Join(dataDir, "server", "ssh_host_dsa_key"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigSkipsUnsupportedHostKey(t *testing.T) {
	gtw := newTestGateway(t)
	writeDSAKey(t, gtw.dataDir)
	if err := gtw.LoadConfig(); err != nil {
		t.Fatalf("expected DSA host key to be skipped, got %v", err)
	}
}

func TestLoadConfigRequiresUsableHostKey(t *testing.T) {
	gtw := newTestGateway(t)
	if err := os.Remove(filepath.Join(gtw.dataDir, "server", "ssh_host_ed25519_key")); err != nil {
		t.Fatal(err)
	}
	writeDSAKey(t, gtw.dataDir)
	if err := gtw.LoadConfig(); err == nil {
		t.Fatal("expected error when only an unsupported host key is present")
	}
}
