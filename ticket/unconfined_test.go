package ticket

import (
	"errors"
	"testing"
)

// TestFlagsUnconfinedOldHub: flags.unconfined is omitted when false, so a
// hub built before it (whose Flags lacks the member) still takes every
// confined ticket and refuses an unconfined one (fail closed).
func TestFlagsUnconfinedOldHub(t *testing.T) {
	type oldFlags struct {
		Production bool   `json:"production"`
		NeverAuto  bool   `json:"never_auto"`
		Retype     string `json:"retype"`
	}
	confined, err := Canonical(Flags{Production: true})
	if err != nil {
		t.Fatal(err)
	}
	var o oldFlags
	if err := decodeStrict(confined, &o); err != nil || !o.Production {
		t.Fatalf("an old hub refuses a confined ticket's flags: %v", err)
	}
	unconfined, err := Canonical(Flags{Unconfined: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrict(unconfined, &o); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an old hub takes an unconfined ticket's flags: %v", err)
	}
	var n Flags
	if err := decodeStrict(unconfined, &n); err != nil || !n.Unconfined {
		t.Fatalf("this hub: %+v, %v", n, err)
	}
}
