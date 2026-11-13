package managed

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/update"
)

const sample = `version = 1
organisation = "Example Corp"

[family]
require_confined_agent = true
vault = { address = "https://vault.example.com", required = true }

[locksql.bounds]
tier = "write"
limits.max_rows = 10000

[locksql.defaults]
limits.statement_timeout = "30s"

[locksql.profiles.prod-erp]
host = "erp.db.example.internal"
production = true

[lox]
allow_no_upgrade = false
`

// testSource reads dir/managed.toml with a fake owner: uid for every path,
// verify for the signature.
func testSource(t *testing.T, uid uint32, verify func([]byte, []byte, update.Identity) error) (*Source, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "lockfamily")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newSource(filepath.Join(dir, FileName))
	s.owner = func(fs.FileInfo) (uint32, bool) { return uid, true }
	s.verify = func(_ context.Context, a, b []byte, id update.Identity) error {
		if verify == nil {
			return errors.New("no verifier")
		}
		return verify(a, b, id)
	}
	return s, dir
}

func write(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAbsentIsNoPolicy(t *testing.T) {
	s, _ := testSource(t, 0, nil)
	f, err := s.Load(context.Background())
	if f != nil || err != nil {
		t.Fatalf("absent file: %v, %v", f, err)
	}
	if (&Source{}).path != "" {
		t.Fatal("zero source has a path")
	}
}

func TestLoadParsesSections(t *testing.T) {
	s, dir := testSource(t, 0, nil)
	write(t, filepath.Join(dir, FileName), sample, 0o644)
	f, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.Organisation != "Example Corp" || !f.RequireConfinedAgent() || f.Family.Vault == nil || !f.Family.Vault.Required || f.Signed {
		t.Fatalf("file %+v", f)
	}
	if len(f.Fingerprint) != 64 || !strings.HasPrefix(f.Describe(), "Managed by Example Corp (sha256:"+f.Fingerprint[:12]) {
		t.Fatalf("fingerprint %q, describe %q", f.Fingerprint, f.Describe())
	}
	var b struct {
		Tier   string `toml:"tier"`
		Limits struct {
			MaxRows int `toml:"max_rows"`
		} `toml:"limits"`
	}
	if ok, err := f.Decode(&b, "locksql", KindBounds); !ok || err != nil || b.Tier != "write" || b.Limits.MaxRows != 10000 {
		t.Fatalf("bounds %+v, %v, %v", b, ok, err)
	}
	var strict struct {
		Tier string `toml:"tier"`
	}
	if _, err := f.Decode(&strict, "locksql", KindBounds); err == nil || !strings.Contains(err.Error(), `unknown key "limits"`) {
		t.Fatalf("unknown bound key not refused: %v", err)
	}
	if ok, err := f.Decode(&strict, "lockmq", KindBounds); ok || err != nil {
		t.Fatalf("absent section: %v, %v", ok, err)
	}
	if got := f.Profiles("locksql"); len(got) != 1 || got[0] != "prod-erp" {
		t.Fatalf("profiles %v", got)
	}
	if !f.Has("lox") || f.Has("lockmq") {
		t.Fatal("Has")
	}
	var nilFile *File
	if nilFile.RequireConfinedAgent() || nilFile.Has("lox") || nilFile.Profiles("locksql") != nil {
		t.Fatal("nil file")
	}
	if ok, err := nilFile.Decode(&strict, "locksql", KindBounds); ok || err != nil {
		t.Fatal("nil file decode")
	}
}

// Defaults overlay: what the file sets is replaced, the rest kept.
func TestDecodeOverlays(t *testing.T) {
	f, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	type limits struct {
		StatementTimeout string `toml:"statement_timeout"`
		MaxRows          int    `toml:"max_rows"`
	}
	v := struct {
		Limits limits `toml:"limits"`
	}{Limits: limits{StatementTimeout: "10s", MaxRows: 5}}
	if ok, err := f.Decode(&v, "locksql", KindDefaults); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if v.Limits.StatementTimeout != "30s" || v.Limits.MaxRows != 5 {
		t.Fatalf("overlay %+v", v)
	}
}

func TestParseRefuses(t *testing.T) {
	for name, data := range map[string]string{
		"no version":        "organisation = \"x\"\n",
		"version 2":         "version = 2\n",
		"unknown top key":   "version = 1\nfoo = 1\n",
		"unknown tool":      "version = 1\n[lockfoo.bounds]\ntier = \"read\"\n",
		"unknown kind":      "version = 1\n[locksql.enforced]\ntier = \"read\"\n",
		"family key":        "version = 1\n[family]\nallow_everything = true\n",
		"family type":       "version = 1\n[family]\nrequire_signature = \"yes\"\n",
		"secret":            "version = 1\n[locksql.profiles.p]\npassword = \"x\"\n",
		"bad profile name":  "version = 1\n[locksql.profiles.\"-p\"]\nhost = \"h\"\n",
		"profile not table": "version = 1\n[locksql.profiles]\np = 1\n",
		"bounds not table":  "version = 1\n[locksql]\nbounds = 1\n",
		"invalid toml":      "version = 1\n[locksql\n",
		"control char org":  "version = 1\norganisation = \"a\\u001b[2Jb\"\n",
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// locklog is not read in v1, but its section is valid.
	if _, err := Parse([]byte("version = 1\n[locklog.bounds]\nx = 1\n")); err != nil {
		t.Fatal(err)
	}
}

// A badly owned or writable file or directory is a refusal, never ignored.
func TestLoadRefusesBadOwnership(t *testing.T) {
	s, dir := testSource(t, 1000, nil)
	path := filepath.Join(dir, FileName)
	write(t, path, sample, 0o644)
	if _, err := s.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "must be owned by root (it is owned by uid 1000)") {
		t.Fatalf("user-owned file: %v", err)
	}

	s, dir = testSource(t, 0, nil)
	path = filepath.Join(dir, FileName)
	write(t, path, sample, 0o666)
	if _, err := s.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "writable by root only") {
		t.Fatalf("world-writable file: %v", err)
	}
	write(t, path, sample, 0o644)
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(context.Background()); err == nil || !strings.Contains(err.Error(), dir+" must be writable by root only") {
		t.Fatalf("group-writable directory: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	// The owner of the directory is checked on its own.
	s.owner = func(fi fs.FileInfo) (uint32, bool) {
		if fi.IsDir() {
			return 501, true
		}
		return 0, true
	}
	if _, err := s.Load(context.Background()); err == nil || !strings.Contains(err.Error(), dir+" must be owned by root") {
		t.Fatalf("user-owned directory: %v", err)
	}
	s.owner = func(fs.FileInfo) (uint32, bool) { return 0, false }
	if _, err := s.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "cannot read the owner") {
		t.Fatalf("unknown owner: %v", err)
	}

	// A symlink is refused, whatever it points to.
	s, dir = testSource(t, 0, nil)
	target := filepath.Join(t.TempDir(), "elsewhere.toml")
	write(t, target, sample, 0o644)
	if err := os.Symlink(target, filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink: %v", err)
	}
}

func TestLoadRefusesInvalidFile(t *testing.T) {
	s, dir := testSource(t, 0, nil)
	write(t, filepath.Join(dir, FileName), "version = 1\n[locksql.bounds\n", 0o644)
	if _, err := s.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid TOML at line") {
		t.Fatalf("invalid file: %v", err)
	}
}

const signerTOML = "certificate_identity_regexp = \"^https://github.com/example/fleet/\"\noidc_issuer = \"https://token.actions.githubusercontent.com\"\n"

func TestSignature(t *testing.T) {
	ctx := context.Background()
	calls := 0
	good := func(a, b []byte, id update.Identity) error {
		calls++
		if string(b) != "bundle" || id.OIDCIssuer != "https://token.actions.githubusercontent.com" {
			return errors.New("bad")
		}
		return nil
	}

	// Absent and not required: OK, unsigned.
	s, dir := testSource(t, 0, good)
	path := filepath.Join(dir, FileName)
	write(t, path, sample, 0o644)
	if f, err := s.Load(ctx); err != nil || f.Signed {
		t.Fatalf("unsigned: %v, %v", f, err)
	}

	// Absent and required: refused.
	write(t, path, "version = 1\n[family]\nrequire_signature = true\n", 0o644)
	if _, err := s.Load(ctx); err == nil || !strings.Contains(err.Error(), "require_signature is set but "+BundleName+" is missing") {
		t.Fatalf("required, absent: %v", err)
	}

	// Present without a signer identity: refused.
	write(t, filepath.Join(dir, BundleName), "bundle", 0o644)
	if _, err := s.Load(ctx); err == nil || !strings.Contains(err.Error(), SignerName) {
		t.Fatalf("no signer: %v", err)
	}

	// Present and valid: signed; verified once while nothing changes.
	write(t, filepath.Join(dir, SignerName), signerTOML, 0o644)
	f, err := s.Load(ctx)
	if err != nil || !f.Signed || !strings.Contains(f.Describe(), ", signed)") {
		t.Fatalf("signed: %v, %v", f, err)
	}
	if _, err := s.Load(ctx); err != nil || calls != 1 {
		t.Fatalf("verified %d times, %v", calls, err)
	}

	// Present and invalid: refused, even when not required.
	write(t, path, sample, 0o644)
	write(t, filepath.Join(dir, BundleName), "forged", 0o644)
	if _, err := s.Load(ctx); err == nil || !strings.Contains(err.Error(), "the signature does not verify") {
		t.Fatalf("invalid signature: %v", err)
	}

	// The signer identity is root-owned too, and strict.
	write(t, filepath.Join(dir, BundleName), "bundle", 0o644)
	write(t, filepath.Join(dir, SignerName), signerTOML, 0o666)
	if _, err := s.Load(ctx); err == nil || !strings.Contains(err.Error(), "writable by root only") {
		t.Fatalf("writable signer: %v", err)
	}
	write(t, filepath.Join(dir, SignerName), "certificate_identity_regexp = \".*\"\noidc_issuer = \"https://x\"\n", 0o644)
	if _, err := s.Load(ctx); err == nil || !strings.Contains(err.Error(), "anchored") {
		t.Fatalf("unanchored signer: %v", err)
	}
}

// The real verifier refuses without cosign: a missing tool never skips.
func TestSignatureWithoutCosignRefuses(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	s, dir := testSource(t, 0, nil)
	s.verify = newSource("").verify
	write(t, filepath.Join(dir, FileName), sample, 0o644)
	write(t, filepath.Join(dir, BundleName), "bundle", 0o644)
	write(t, filepath.Join(dir, SignerName), signerTOML, 0o644)
	if _, err := s.Load(context.Background()); !errors.Is(err, update.ErrCosignMissing) {
		t.Fatalf("no cosign: %v", err)
	}
}

func TestDefaultPath(t *testing.T) {
	p := DefaultPath()
	if p != "/etc/lockfamily/managed.toml" && p != "/Library/Application Support/lockfamily/managed.toml" && p != "" {
		t.Fatalf("path %q", p)
	}
	if std.path != p || std.skipOwner {
		t.Fatal("the machine's source is not the OS path with the owner check")
	}
}

// pol is a policy with a ranked tier, a row limit (0 unlimited) and a
// credentials mode.
type pol struct {
	Tier        string
	MaxRows     int64
	Credentials string
}

var rank = map[string]int{"read": 0, "write": 1, "ddl": 2}

func (p pol) Diff(approved config.Policy) []config.Change {
	a := approved.(pol)
	var out []config.Change
	if a.Tier != p.Tier {
		out = append(out, config.Change{Field: "tier", Old: a.Tier, New: p.Tier, Loosens: rank[p.Tier] > rank[a.Tier]})
	}
	if a.MaxRows != p.MaxRows {
		out = append(out, config.Change{Field: "limits.max_rows", Old: strconv.FormatInt(a.MaxRows, 10), New: strconv.FormatInt(p.MaxRows, 10),
			Loosens: config.LooserLimit(a.MaxRows, p.MaxRows)})
	}
	if a.Credentials != p.Credentials {
		out = append(out, config.Change{Field: "credentials", Old: a.Credentials, New: p.Credentials, Loosens: true})
	}
	return out
}

func (p pol) Describe() []string { return nil }

func TestCheck(t *testing.T) {
	ceiling := pol{Tier: "write", MaxRows: 10000, Credentials: "vault"}
	b := Bounds{Tool: "locksql", Profile: "dev", Ceiling: ceiling}
	if v := Check(pol{Tier: "read", MaxRows: 100, Credentials: "vault"}, b); len(v) != 0 {
		t.Fatalf("tighter policy refused: %v", v)
	}
	if v := Check(ceiling, b); len(v) != 0 {
		t.Fatalf("policy at the bounds refused: %v", v)
	}
	v := Check(pol{Tier: "ddl", MaxRows: 0, Credentials: "keychain"}, b)
	if len(v) != 3 {
		t.Fatalf("violations %v", v)
	}
	if got := v[0].String(); got != "blocked by company policy: locksql.bounds.tier = write (profile dev: tier = ddl)" {
		t.Fatalf("message %q", got)
	}
	if v[1].Key != "locksql.bounds.limits.max_rows" || v[1].Value != "0" {
		t.Fatalf("unlimited rows: %+v", v[1])
	}
	b.Keys = map[string]string{"credentials": "credentials_allowed"}
	if v := Check(pol{Tier: "read", MaxRows: 1, Credentials: "keychain"}, b); len(v) != 1 || v[0].Key != "locksql.bounds.credentials_allowed" {
		t.Fatalf("mapped key: %v", v)
	}
	if Check(ceiling, Bounds{Tool: "locksql"}) != nil {
		t.Fatal("no ceiling bounds something")
	}
	if s := (Violation{Key: "k", Profile: "p", Field: "hosts", Value: "evil"}).String(); !strings.Contains(s, "does not allow evil") {
		t.Fatal(s)
	}
	if s := (Violation{Key: "k", Profile: "p", Field: "detectors", Bound: "email"}).String(); !strings.Contains(s, "requires email") {
		t.Fatal(s)
	}
}

func TestClampDuration(t *testing.T) {
	h := time.Hour
	for _, c := range []struct{ conf, max, want time.Duration }{
		{0, 8 * h, 8 * h}, {-1, 8 * h, 8 * h}, {h, 8 * h, h}, {9 * h, 8 * h, 8 * h}, {9 * h, 0, 9 * h}, {0, 0, 0},
	} {
		if got := ClampDuration(c.conf, c.max); got != c.want {
			t.Errorf("ClampDuration(%v, %v) = %v, want %v", c.conf, c.max, got, c.want)
		}
	}
}

func TestMergeProfiles(t *testing.T) {
	m, err := MergeProfiles(map[string]string{"prod-erp": "managed"}, map[string]string{"dev": "project"}, map[string]string{"dev": "user", "uat": "user"})
	if err != nil {
		t.Fatal(err)
	}
	if m["prod-erp"] != "managed" || m["dev"] != "project" || m["uat"] != "user" || len(m) != 3 {
		t.Fatalf("merged %v", m)
	}
	for _, c := range []struct {
		project, user map[string]string
		where         string
	}{{map[string]string{"prod-erp": "mine"}, nil, "project"}, {nil, map[string]string{"prod-erp": "mine"}, "user"}} {
		_, err := MergeProfiles(map[string]string{"prod-erp": "managed"}, c.project, c.user)
		if err == nil || !strings.Contains(err.Error(), "cannot be redefined in the "+c.where+" config") {
			t.Fatalf("%s redefinition: %v", c.where, err)
		}
	}
}

// signedSource writes a signed managed file in a fresh directory; its
// verifier fails the test when called.
func signedSource(t *testing.T) (*Source, string) {
	t.Helper()
	s, dir := testSource(t, 0, func([]byte, []byte, update.Identity) error {
		t.Error("the verifier was called despite a matching stamp")
		return errors.New("called")
	})
	write(t, filepath.Join(dir, FileName), sample, 0o644)
	write(t, filepath.Join(dir, BundleName), "bundle", 0o644)
	write(t, filepath.Join(dir, SignerName), signerTOML, 0o644)
	return s, dir
}

// stampOf is the stamp of dir's files, as lox computes it on the host.
func stampOf(t *testing.T, dir string) string {
	t.Helper()
	s, _ := testSource(t, 0, func([]byte, []byte, update.Identity) error { return nil })
	s.path = filepath.Join(dir, FileName)
	f, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stamp, err := VerifiedStamp(f)
	if err != nil {
		t.Fatal(err)
	}
	return stamp
}

// A stamp lox wrote for these exact bytes stands for the signature check.
func TestVerifiedStampMatches(t *testing.T) {
	s, dir := signedSource(t)
	stamp := stampOf(t, dir)
	if !strings.HasPrefix(stamp, "sha256:") || len(stamp) != len("sha256:")+64 {
		t.Fatalf("stamp %q", stamp)
	}
	write(t, filepath.Join(dir, VerifiedName), stamp+"\n", 0o644)
	f, err := s.Load(context.Background())
	if err != nil || !f.Signed {
		t.Fatalf("stamped: %v, %v", f, err)
	}
	if again, err := VerifiedStamp(f); err != nil || again != stamp {
		t.Fatalf("stamp of a stamped file: %q, %v", again, err)
	}
	// Without the trailing newline too.
	write(t, filepath.Join(dir, VerifiedName), stamp, 0o644)
	s.cached = nil
	if f, err := s.Load(context.Background()); err != nil || !f.Signed {
		t.Fatalf("stamp without newline: %v, %v", f, err)
	}
}

// A stamp written for other bytes is a refusal: the signature is not
// checked instead.
func TestVerifiedStampMismatchRefuses(t *testing.T) {
	for _, tc := range []struct{ name, file, data string }{
		{"file", FileName, sample + "\n"},
		{"bundle", BundleName, "other bundle"},
		{"signer", SignerName, signerTOML + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, dir := signedSource(t)
			write(t, filepath.Join(dir, VerifiedName), stampOf(t, dir)+"\n", 0o644)
			if _, err := s.Load(context.Background()); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(dir, tc.file), tc.data, 0o644)
			if _, err := s.Load(context.Background()); err == nil || !strings.Contains(err.Error(), VerifiedName+" does not match") {
				t.Fatalf("%s changed: %v", tc.name, err)
			}
		})
	}
	s, dir := signedSource(t)
	write(t, filepath.Join(dir, VerifiedName), "garbage\n", 0o644)
	if _, err := s.Load(context.Background()); err == nil || !strings.Contains(err.Error(), VerifiedName) {
		t.Fatalf("garbage stamp: %v", err)
	}
}

// The stamp is root-owned like managed.toml.
func TestVerifiedStampOwnership(t *testing.T) {
	s, dir := signedSource(t)
	stamp := stampOf(t, dir)
	path := filepath.Join(dir, VerifiedName)
	write(t, path, stamp, 0o666)
	if _, err := s.Load(context.Background()); err == nil || !strings.Contains(err.Error(), path+" must be writable by root only") {
		t.Fatalf("writable stamp: %v", err)
	}
	write(t, path, stamp, 0o644)
	s.owner = func(fi fs.FileInfo) (uint32, bool) {
		if filepath.Base(fi.Name()) == VerifiedName {
			return 1000, true
		}
		return 0, true
	}
	if _, err := s.Load(context.Background()); err == nil || !strings.Contains(err.Error(), path+" must be owned by root") {
		t.Fatalf("user-owned stamp: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, SignerName), path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlinked stamp: %v", err)
	}
}

// No stamp: the verifier runs as before. No bundle: a stamp is ignored.
func TestVerifiedStampAbsentOrUnsigned(t *testing.T) {
	calls := 0
	s, dir := testSource(t, 0, func([]byte, []byte, update.Identity) error { calls++; return nil })
	write(t, filepath.Join(dir, FileName), sample, 0o644)
	write(t, filepath.Join(dir, BundleName), "bundle", 0o644)
	write(t, filepath.Join(dir, SignerName), signerTOML, 0o644)
	if f, err := s.Load(context.Background()); err != nil || !f.Signed || calls != 1 {
		t.Fatalf("no stamp: %v, %v, %d calls", f, err, calls)
	}

	if err := os.Remove(filepath.Join(dir, BundleName)); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, VerifiedName), "garbage", 0o666)
	f, err := s.Load(context.Background())
	if err != nil || f.Signed || calls != 1 {
		t.Fatalf("no bundle, stamp: %v, %v, %d calls", f, err, calls)
	}
	if _, err := VerifiedStamp(f); err == nil {
		t.Fatal("stamp of an unsigned file")
	}
	if _, err := VerifiedStamp(nil); err == nil {
		t.Fatal("stamp of no file")
	}
	parsed, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	parsed.Signed = true
	if _, err := VerifiedStamp(parsed); err == nil {
		t.Fatal("stamp of a file Load did not read")
	}
}

func TestDecodeNestedIntoMap(t *testing.T) {
	f, err := Parse([]byte(`version = 1
[lockmq.defaults]
tier = "read"
limits = { max_rows = 10 }
[lockmq.defaults.queue]
size = 5
[lockmq.defaults.deep.inner]
x = 1
[[lockmq.defaults.rules]]
name = "a"
[[lockmq.defaults.rules]]
name = "b"
`))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if ok, err := f.Decode(&m, "lockmq", KindDefaults); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if l, _ := m["limits"].(map[string]any); l["max_rows"] != int64(10) {
		t.Fatalf("limits %#v", m["limits"])
	}
	if q, _ := m["queue"].(map[string]any); q["size"] != int64(5) {
		t.Fatalf("queue %#v", m["queue"])
	}
	if d, _ := m["deep"].(map[string]any); d["inner"].(map[string]any)["x"] != int64(1) {
		t.Fatalf("deep %#v", m["deep"])
	}
	if r, _ := m["rules"].([]map[string]any); len(r) != 2 || r[1]["name"] != "b" {
		t.Fatalf("rules %#v", m["rules"])
	}
	var a any
	if ok, err := f.Decode(&a, "lockmq", KindDefaults); !ok || err != nil {
		t.Fatal(ok, err)
	}
}

func TestDecodeMapFieldStaysStrictElsewhere(t *testing.T) {
	f, err := Parse([]byte(`version = 1
[lockmq.defaults]
tier = "read"
[lockmq.defaults.extra]
anything = 1
[lockmq.defaults.extra.sub]
y = 2
[lockmq.defaults.limits]
max_rows = 10
[[lockmq.defaults.rules]]
name = "a"
opts = { k = 1 }
`))
	if err != nil {
		t.Fatal(err)
	}
	type limits struct {
		MaxRows int `toml:"max_rows"`
	}
	type rule struct {
		Name string         `toml:"name"`
		Opts map[string]any `toml:"opts"`
	}
	type defaults struct {
		Tier   string         `toml:"tier"`
		Extra  map[string]any `toml:"extra"`
		Limits limits         `toml:"limits"`
		Rules  []rule         `toml:"rules"`
	}
	var v defaults
	if ok, err := f.Decode(&v, "lockmq", KindDefaults); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if v.Extra["sub"].(map[string]any)["y"] != int64(2) || v.Limits.MaxRows != 10 || v.Rules[0].Opts["k"] != int64(1) {
		t.Fatalf("decoded %+v", v)
	}
	for key, data := range map[string]string{
		"limits.min_rows": "version = 1\n[lockmq.defaults.limits]\nmin_rows = 1\n",
		"rules.label":     "version = 1\n[[lockmq.defaults.rules]]\nlabel = \"x\"\n",
		"other":           "version = 1\n[lockmq.defaults]\nother = 1\n",
	} {
		f, err := Parse([]byte(data))
		if err != nil {
			t.Fatal(key, err)
		}
		var v defaults
		if _, err := f.Decode(&v, "lockmq", KindDefaults); err == nil || !strings.Contains(err.Error(), "unknown key \""+key+"\"") {
			t.Errorf("%s: %v", key, err)
		}
	}
}
