//go:build unix

package console

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/config"
)

// The production profile name is typed when a policy is approved, not at
// every start: a restart of an approved, unchanged production profile
// goes straight to the credentials (#127), as locksql does. The review
// itself takes the typed name on production, never "y" (#8), and the
// start does not ask it a second time.
func TestRunProductionNameOnlyOnApproval(t *testing.T) {
	env := runEnv(t)
	state := t.TempDir()
	const review = `Apply these changes? Type the profile name "prod" to apply them: `
	const name = `Type the profile name "prod" to continue: `
	pol := prod()
	run := func(answers ...string) *fakeIO {
		t.Helper()
		io := &fakeIO{answers: answers}
		// Ends at the password prompt, which gets no answer.
		_ = Run(context.Background(), testProduct, &fakeBackend{policy: pol}, Options{Profile: "prod", Hub: testHub(t), IO: io,
			StateDir: state, Isolation: env, Harden: func() error { return nil }})
		return io
	}
	asked := func(io *fakeIO, prompt string) bool {
		for _, p := range io.promptList() {
			if strings.Contains(p, prompt) {
				return true
			}
		}
		return false
	}
	reachedPassword := func(t *testing.T, io *fakeIO) {
		t.Helper()
		if !asked(io, "Password for ro@broker.example.com") {
			t.Fatalf("the start did not reach the password: %q\n%s", io.promptList(), io.plain())
		}
	}

	// First approval: "y" and a wrong case refuse the review.
	for _, ans := range []string{"y", "PROD"} {
		io := run(ans)
		if !asked(io, review) || asked(io, "[y/N]") || asked(io, "Password for") {
			t.Fatalf("first start answered %q, prompts: %q", ans, io.promptList())
		}
	}
	// The typed name approves it, and is not asked again.
	io := run("prod")
	if !asked(io, review) || asked(io, name) {
		t.Fatalf("first start prompts: %q", io.promptList())
	}
	reachedPassword(t, io)

	// Plain restart: no name, the banner still shows.
	io = run()
	if asked(io, name) || asked(io, review) {
		t.Fatalf("restart of an unchanged approved profile asked the name: %q", io.promptList())
	}
	if !strings.Contains(io.plain(), "PRODUCTION profile prod") || !strings.Contains(io.plain(), "profile name typed at an earlier start") {
		t.Errorf("no production banner or note:\n%s", io.plain())
	}
	reachedPassword(t, io)

	// A tightening applies without a review, and without the name.
	pol.MaxRows = 10
	io = run()
	if asked(io, "Apply these changes") || asked(io, name) {
		t.Fatalf("tightening prompts: %q", io.promptList())
	}
	reachedPassword(t, io)

	// A loosening is reviewed with the typed name; "y" refuses it and
	// the approved policy stays.
	pol.MaxRows = 500
	io = run("y")
	if !asked(io, review) || asked(io, name) || !strings.Contains(io.plain(), "changes refused") {
		t.Fatalf("loosening answered y: %q\n%s", io.promptList(), io.plain())
	}
	reachedPassword(t, io)
	io = run("prod")
	if !asked(io, review) || asked(io, name) {
		t.Fatalf("loosening prompts: %q", io.promptList())
	}
	reachedPassword(t, io)
	io = run()
	if asked(io, name) || asked(io, review) {
		t.Fatalf("restart after the reviewed loosening asked: %q", io.promptList())
	}

	// Turning production off loosens a production profile: the name.
	pol.Production = false
	io = run("y")
	if !asked(io, review) || !strings.Contains(io.plain(), "changes refused") {
		t.Fatalf("production off answered y: %q\n%s", io.promptList(), io.plain())
	}
	pol.Production = true

	// Deleting the approval brings back the first-start review, with the
	// name, even for the very policy confirmed before.
	key := config.ApprovedKey("", "prod")
	if err := os.Remove(filepath.Join(state, testProduct.Name, "approved", key+".json")); err != nil {
		t.Fatal(err)
	}
	io = run("prod")
	if !asked(io, review) || asked(io, name) {
		t.Fatalf("re-approval prompts: %q", io.promptList())
	}
	reachedPassword(t, io)

	// An approved policy whose name was never recorded as typed (a lost
	// record, an approval from before the record) asks it to continue.
	if err := os.Remove(filepath.Join(state, testProduct.Name, "approved", ConfirmedKey(key)+".json")); err != nil {
		t.Fatal(err)
	}
	io = run("nope")
	if asked(io, review) || !asked(io, name) || asked(io, "Password for") {
		t.Fatalf("unconfirmed production prompts: %q", io.promptList())
	}
	io = run("prod")
	if !asked(io, name) {
		t.Fatalf("unconfirmed production prompts: %q", io.promptList())
	}
	reachedPassword(t, io)
}

func TestProductionNameNeeded(t *testing.T) {
	state := t.TempDir()
	const key = "user-prod"
	p := prod()
	if !productionNameNeeded(testProduct, state, key, p, false) {
		t.Fatal("no record: the name must be asked")
	}
	if err := config.SaveApproved(testProduct, state, ConfirmedKey(key), p); err != nil {
		t.Fatal(err)
	}
	if productionNameNeeded(testProduct, state, key, p, false) {
		t.Fatal("the confirmed policy itself: no name")
	}
	if !productionNameNeeded(testProduct, state, key, p, true) {
		t.Fatal("a review approved at this start asks the name")
	}
	looser := p
	looser.Tier = "peek"
	if !productionNameNeeded(testProduct, state, key, looser, false) {
		t.Fatal("a policy looser than the confirmed one asks the name")
	}
	tighter := p
	tighter.MaxRows = 1
	if productionNameNeeded(testProduct, state, key, tighter, false) {
		t.Fatal("a tighter policy does not ask the name")
	}
	np := p
	np.Production = false
	if err := config.SaveApproved(testProduct, state, ConfirmedKey(key), np); err != nil {
		t.Fatal(err)
	}
	if !productionNameNeeded(testProduct, state, key, p, false) {
		t.Fatal("a name never typed for a production policy is asked")
	}
	path := filepath.Join(state, testProduct.Name, "approved", ConfirmedKey(key)+".json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !productionNameNeeded(testProduct, state, key, p, false) {
		t.Fatal("an unreadable record asks the name")
	}
}
