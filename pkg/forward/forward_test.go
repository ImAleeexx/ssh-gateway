package forward

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"

	"go.htdvisser.nl/ssh-gateway/pkg/encoding"
	"go.htdvisser.nl/ssh-gateway/pkg/log"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// connect returns an SSH client connected to an in-memory SSH server whose
// channels and requests are handled by handle.
func connect(t *testing.T, handle func(<-chan ssh.NewChannel, <-chan *ssh.Request)) *ssh.Client {
	t.Helper()
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(newSigner(t))
	// net.Pipe can not be used: it is unbuffered, and both sides of an SSH
	// handshake write their version at the same time.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go func() {
		serverNetConn, err := lis.Accept()
		if err != nil {
			return
		}
		_, chans, reqs, err := ssh.NewServerConn(serverNetConn, serverConfig)
		if err != nil {
			return
		}
		handle(chans, reqs)
	}()
	clientNetConn, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(clientNetConn, lis.Addr().String(), &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { client.Close() })
	return client
}

// upstream runs exec requests by writing stdout and stderr and returning exit status 7.
func upstream(chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.Prohibited, "only sessions are allowed")
			continue
		}
		ch, chReqs, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range chReqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)
				ch.Write([]byte("out"))
				ch.Stderr().Write([]byte("err"))
				ch.SendRequest("exit-status", false, encoding.Uint32(7))
				ch.Close()
			}
		}()
	}
}

func newGateway(t *testing.T) *ssh.Client {
	t.Helper()
	target := connect(t, upstream)
	ctx, cancel := context.WithCancel(log.NewContext(context.Background(), zap.NewNop()))
	t.Cleanup(cancel)
	return connect(t, func(chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		go Requests(ctx, target, reqs)
		Channels(ctx, target, chans)
	})
}

func TestForwardExitStatusAndStderr(t *testing.T) {
	client := newGateway(t)
	// The exit status used to be lost in most runs, so repeat the test.
	for i := 0; i < 50; i++ {
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		session.Stdout, session.Stderr = &stdout, &stderr
		err = session.Run("anything")
		var exitErr *ssh.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 7 {
			t.Fatalf("run %d: expected exit status 7, got %v", i, err)
		}
		if stdout.String() != "out" || stderr.String() != "err" {
			t.Fatalf("run %d: expected stdout %q and stderr %q, got %q and %q", i, "out", "err", stdout.String(), stderr.String())
		}
	}
}

func TestForwardContinuesAfterRejectedChannel(t *testing.T) {
	client := newGateway(t)
	_, _, err := client.OpenChannel("direct-tcpip", nil)
	var openErr *ssh.OpenChannelError
	if !errors.As(err, &openErr) || openErr.Reason != ssh.Prohibited {
		t.Fatalf("expected channel to be rejected as prohibited, got %v", err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("expected new session after rejected channel, got %v", err)
	}
	defer session.Close()
	if _, err := session.Output("anything"); err == nil {
		t.Fatal("expected exit status error")
	}
}
