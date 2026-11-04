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
// goes straight to the credentials (#127), as locksql does.
func TestRunProductionNameOnlyOnApproval(t *testing.T) {
	env := runEnv(t)
	state := t.TempDir()
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

	// First approval: the review, then the name; a wrong one stops.
	io := run("y", "nope")
	if !asked(io, "Apply these changes") || !asked(io, name) {
		t.Fatalf("first start prompts: %q", io.promptList())
	}
	if asked(io, "Password for") {
		t.Fatal("a wrong name went on to the credentials")
	}
	// The name was not confirmed: the approved policy alone does not skip it.
	io = run("prod")
	if asked(io, "Apply these changes") || !asked(io, name) {
		t.Fatalf("after a wrong name, prompts: %q", io.promptList())
	}
	reachedPassword(t, io)

	// Plain restart: no name, the banner still shows.
	io = run()
	if asked(io, name) {
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

	// A loosening is reviewed, and the name is asked again.
	pol.MaxRows = 500
	io = run("y", "prod")
	if !asked(io, "Apply these changes") || !asked(io, name) {
		t.Fatalf("loosening prompts: %q", io.promptList())
	}
	reachedPassword(t, io)
	io = run()
	if asked(io, name) {
		t.Fatalf("restart after the reviewed loosening asked the name: %q", io.promptList())
	}

	// A refused loosening keeps the approved policy, already confirmed.
	pol.MaxRows = 900
	io = run("n")
	if !asked(io, "Apply these changes") || asked(io, name) {
		t.Fatalf("refused loosening prompts: %q", io.promptList())
	}
	reachedPassword(t, io)

	// Deleting the approval brings back the first-start review, and the
	// name with it, even for the very policy confirmed before.
	pol.MaxRows = 500
	key := config.ApprovedKey("", "prod")
	if err := os.Remove(filepath.Join(state, testProduct.Name, "approved", key+".json")); err != nil {
		t.Fatal(err)
	}
	io = run("y", "prod")
	if !asked(io, "Apply these changes") || !asked(io, name) {
		t.Fatalf("re-approval prompts: %q", io.promptList())
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
