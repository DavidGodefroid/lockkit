//go:build unix

package console

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/secrets"
)

const vaultTestPath = "database/creds/orders"

// vaultStarter is a starter wired for credentials = "vault": the test IO
// answers the token prompts with tokens, read stands for Vault.
func vaultStarter(t *testing.T, io *fakeIO, now func() time.Time, read func(context.Context, string, []byte) (*secrets.VaultCredentials, error)) (*starter, *audit.Log) {
	t.Helper()
	t.Setenv("VAULT_ADDR", "https://vault.example.com:8200")
	log, err := audit.Open(testProduct, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{policy: uat()}
	return &starter{b: b, o: Options{Now: now}, io: io, log: log, vaultRead: read,
		profile: Profile{Name: "uat", Host: "broker.example.com", User: "ro", VaultPath: vaultTestPath}}, log
}

func noVaultToken(t *testing.T, out string, log *audit.Log, token string) {
	t.Helper()
	if strings.Contains(out, token) {
		t.Fatalf("the token is in the output:\n%s", out)
	}
	if raw, err := os.ReadFile(log.Path()); err == nil && strings.Contains(string(raw), token) {
		t.Fatalf("the token is in the audit trail:\n%s", raw)
	}
}

func TestConnectVaultAsksTheTokenAtStart(t *testing.T) {
	io := &fakeIO{secrets: []string{"s.token-1"}}
	var got []byte
	st, log := vaultStarter(t, io, time.Now, func(_ context.Context, path string, token []byte) (*secrets.VaultCredentials, error) {
		if path != vaultTestPath {
			t.Errorf("path %q", path)
		}
		got = append([]byte(nil), token...)
		return &secrets.VaultCredentials{User: "ro", Password: []byte("vpw")}, nil
	})
	sess, err := st.connectVault(context.Background(), st.profile, func(c Credentials) (Session, error) {
		return st.b.Connect(context.Background(), c)
	}, true)
	if err != nil || sess == nil {
		t.Fatalf("connectVault: %v", err)
	}
	if p := io.promptList(); len(p) != 1 || p[0] != "Vault token for https://vault.example.com:8200: " {
		t.Fatalf("prompts %q", p)
	}
	if string(got) != "s.token-1" {
		t.Fatalf("VaultRead got %q", got)
	}
	noVaultToken(t, io.plain(), log, "s.token-1")
}

func TestConnectVaultRefusedThreeTimes(t *testing.T) {
	io := &fakeIO{secrets: []string{"s.bad-1", "s.bad-2", "s.bad-3", "s.bad-4"}}
	st, log := vaultStarter(t, io, time.Now, func(context.Context, string, []byte) (*secrets.VaultCredentials, error) {
		return nil, fmt.Errorf("%w: permission denied", secrets.ErrVaultAuth)
	})
	_, err := st.connectVault(context.Background(), st.profile, nil, true)
	if !errors.Is(err, secrets.ErrVaultAuth) {
		t.Fatalf("err %v", err)
	}
	if n := io.promptCount(); n != 3 {
		t.Fatalf("%d prompts, want 3", n)
	}
	want := "Vault refused the read: " + secrets.ErrVaultAuth.Error() + ": permission denied. Enter the token again, or a token whose policy may read " + vaultTestPath
	if !strings.Contains(io.plain(), want) {
		t.Fatalf("warning missing:\n%s", io.plain())
	}
	for _, tok := range []string{"s.bad-1", "s.bad-2", "s.bad-3"} {
		noVaultToken(t, io.plain()+err.Error(), log, tok)
	}
}

func TestConnectVaultUnreachableDoesNotAskAgain(t *testing.T) {
	io := &fakeIO{secrets: []string{"s.token-1", "s.token-2"}}
	st, _ := vaultStarter(t, io, time.Now, func(context.Context, string, []byte) (*secrets.VaultCredentials, error) {
		return nil, fmt.Errorf("%w: no answer", secrets.ErrVaultUnreachable)
	})
	_, err := st.connectVault(context.Background(), st.profile, nil, true)
	if err == nil || !strings.Contains(err.Error(), "credentials from Vault ("+vaultTestPath+")") || !strings.Contains(err.Error(), "server unreachable") {
		t.Fatalf("err %v", err)
	}
	if n := io.promptCount(); n != 1 {
		t.Fatalf("%d prompts, want 1", n)
	}
}

// A reconnection (the lease is about to end) reuses the token of the
// session: the human is asked once.
func TestReconnectVaultKeepsTheToken(t *testing.T) {
	io := &fakeIO{secrets: []string{"s.token-1", "s.token-2"}}
	clock := time.Now()
	var tokens []string
	st, _ := vaultStarter(t, io, func() time.Time { return clock }, func(_ context.Context, _ string, token []byte) (*secrets.VaultCredentials, error) {
		tokens = append(tokens, string(token))
		return &secrets.VaultCredentials{User: "ro", Password: []byte("vpw"), LeaseID: "l1", LeaseDuration: 10 * time.Minute}, nil
	})
	open := func(c Credentials) (Session, error) { return st.b.Connect(context.Background(), c) }
	if _, err := st.connectVault(context.Background(), st.profile, open, true); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(9 * time.Minute)
	if _, err := st.connectVault(context.Background(), st.profile, open, false); err != nil {
		t.Fatal(err)
	}
	if n := io.promptCount(); n != 1 {
		t.Fatalf("%d prompts, want 1", n)
	}
	if len(tokens) != 2 || tokens[0] != "s.token-1" || tokens[1] != "s.token-1" {
		t.Fatalf("tokens %q", tokens)
	}
}
