package duo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestAuthenticateRejectsInvalidUsername(t *testing.T) {
	c := &Client{config: &Config{}, dataDir: t.TempDir(), logger: zap.NewNop()}
	for _, username := range []string{"", ".", "..", "../x", "a/b", `a\b`, "a b", "a\nb"} {
		err := c.AuthenticateUser(context.Background(), username, "192.0.2.1")
		if !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("username %q: expected ErrInvalidUsername, got %v", username, err)
		}
	}
}

func TestAuthenticateSkipsUsersWithoutDuo(t *testing.T) {
	c := &Client{config: &Config{}, dataDir: t.TempDir(), logger: zap.NewNop()}
	for _, username := range []string{"alice", "Alice", "alice@example.com"} {
		if err := c.AuthenticateUser(context.Background(), username, "192.0.2.1"); err != nil {
			t.Errorf("username %q: expected Duo to be skipped, got %v", username, err)
		}
	}
}

func TestIsUserDuoEnabled(t *testing.T) {
	dataDir := t.TempDir()
	c := &Client{config: &Config{}, dataDir: dataDir, logger: zap.NewNop()}
	if err := c.CreateUserDuoFile("Alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "users", "duo_enabled_Alice")); err != nil {
		t.Fatal(err)
	}
	if !c.IsUserDuoEnabled("Alice") {
		t.Error("expected Duo to be enabled for Alice")
	}
	if c.IsUserDuoEnabled("bob") {
		t.Error("expected Duo to be disabled for bob")
	}
	if err := c.CreateUserDuoFile("../evil"); err == nil {
		t.Error("expected invalid username to be rejected")
	}
}
