// Package managed reads the company-managed configuration of the lock
// family: one file, set by the company's admin (MDM, Ansible, a package),
// that bounds the policy of every lock, lox and lea on the machine. A user
// may tighten what it allows, never loosen it.
//
// The file is /etc/lockfamily/managed.toml on Linux and
// /Library/Application Support/lockfamily/managed.toml on macOS. It and its
// directory must be owned by root and writable by root only: a badly owned
// file is a refusal to start, never a file ignored, since breaking it
// would otherwise get around it. An optional cosign signature
// (managed.toml.sigstore.json, next to it) is checked against the company
// identity set at install time (signer.toml, root-owned too); a signature
// present but invalid is a refusal, and [family] require_signature = true
// makes it mandatory. A missing file means no managed policy.
//
// Each tool has its section, [<tool>.bounds], [<tool>.defaults] and
// [<tool>.profiles.<name>] for the locks, [lox] and [lea] decoded whole by
// their owner. The precedence is:
//
//	hard-coded floor > managed bounds, enforced values and profiles
//	  > project file > user file > managed defaults > built-in defaults
//
// A product decodes its managed defaults into its config before the user
// and project files (Decode overlays a struct), merges its profiles with
// MergeProfiles (a managed profile wins as a whole and cannot be
// redefined), and the console checks the merged result against the bounds
// (Check) at start and at every policy poll.
package managed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"

	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/update"
)

// File names, in the managed directory.
const (
	FileName   = "managed.toml"
	BundleName = FileName + ".sigstore.json"
	SignerName = "signer.toml"
)

// Version is the only managed file version this package reads.
const Version = 1

// DefaultPath is the managed file of this OS: "" where the family reads
// none yet (Windows).
func DefaultPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/lockfamily/" + FileName
	case "windows":
		return ""
	default:
		return "/etc/lockfamily/" + FileName
	}
}

// Section kinds of a lock's section.
const (
	KindBounds   = "bounds"
	KindDefaults = "defaults"
	KindProfiles = "profiles"
)

// lockTools have [<tool>.bounds|defaults|profiles] sections; wholeTools a
// section their owner decodes whole.
var (
	lockTools  = []string{"lockfile", "lockhttp", "locklog", "lockmq", "locksql", "lockssh"}
	wholeTools = []string{"lea", "lox"}
)

// Family is the [family] section: rules for every tool.
type Family struct {
	// RequireConfinedAgent refuses an agent that does not run confined
	// (lockkit#133).
	RequireConfinedAgent bool `toml:"require_confined_agent"`
	// RequireSignature refuses the managed file unless it is signed.
	RequireSignature bool `toml:"require_signature"`
	// Vault is the Vault every lock uses; each lock enforces it.
	Vault *Vault `toml:"vault"`
}

// Vault is [family] vault: with Required, Vault is the only credential
// source of every lock.
type Vault struct {
	Address   string `toml:"address"`
	Namespace string `toml:"namespace"`
	CA        string `toml:"ca"`
	Required  bool   `toml:"required"`
}

// File is a managed file read and trusted.
type File struct {
	// Path is where it was read ("" when parsed from bytes).
	Path string
	// Fingerprint is the hex sha256 of its bytes, recorded with every
	// approval and audit record made under it.
	Fingerprint  string
	Organisation string
	// Signed: its signature was present and verified.
	Signed bool
	Family Family
	tools  map[string]any
}

// RequireConfinedAgent reports [family] require_confined_agent; false for
// a nil File (no managed policy).
func (f *File) RequireConfinedAgent() bool { return f != nil && f.Family.RequireConfinedAgent }

// Describe is one line for a console's start screen and a tool's
// `managed show`.
func (f *File) Describe() string {
	org := f.Organisation
	if org == "" {
		org = "the company"
	}
	s := fmt.Sprintf("Managed by %s (sha256:%s", org, f.Fingerprint[:12])
	if f.Signed {
		s += ", signed"
	}
	return s + ")"
}

// Has reports whether f has a section for tool (nil File: false).
func (f *File) Has(tool string) bool {
	if f == nil {
		return false
	}
	_, ok := f.tools[tool]
	return ok
}

// Decode decodes the table at key (["locksql", "bounds"], ["lox"],
// ["locksql", "profiles", "prod-erp"]) into into, strictly: a key into does
// not declare is refused. It returns false, into untouched, when f is nil
// or has no such table. into is overlaid, not reset: a product decodes its
// managed defaults first, then its config files over them.
func (f *File) Decode(into any, key ...string) (bool, error) {
	if f == nil || len(key) == 0 {
		return false, nil
	}
	var cur any = f.tools
	for _, k := range key {
		m, ok := cur.(map[string]any)
		if !ok {
			return false, nil
		}
		if cur, ok = m[k]; !ok {
			return false, nil
		}
	}
	m, ok := cur.(map[string]any)
	if !ok {
		return false, fmt.Errorf("managed: %s: [%s] is not a table", f.name(), strings.Join(key, "."))
	}
	if err := decodeTable(m, into); err != nil {
		return false, fmt.Errorf("managed: %s: [%s]: %w", f.name(), strings.Join(key, "."), err)
	}
	return true, nil
}

// Profiles lists the names of tool's managed profiles, sorted.
func (f *File) Profiles(tool string) []string {
	if f == nil {
		return nil
	}
	sec, _ := f.tools[tool].(map[string]any)
	m, _ := sec[KindProfiles].(map[string]any)
	return slices.Sorted(maps.Keys(m))
}

func (f *File) name() string {
	if f.Path == "" {
		return FileName
	}
	return f.Path
}

// decodeTable decodes m into into through TOML, refusing keys into does
// not declare.
func decodeTable(m map[string]any, into any) error {
	b, err := toml.Marshal(m)
	if err != nil {
		return err
	}
	md, err := toml.NewDecoder(bytes.NewReader(b)).Decode(into)
	if err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "toml: "))
	}
	if und := md.Undecoded(); len(und) > 0 {
		return fmt.Errorf("unknown key %q", und[0].String())
	}
	return nil
}

// Parse decodes and validates a managed file's bytes: version 1, known
// sections only, no secret-looking key, valid profile names. It checks
// neither ownership nor signature: Load does.
func Parse(data []byte) (*File, error) {
	var raw map[string]any
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		var pe toml.ParseError
		if errors.As(err, &pe) {
			return nil, fmt.Errorf("invalid TOML at line %d", pe.Position.Line)
		}
		return nil, fmt.Errorf("invalid TOML: %s", strings.TrimPrefix(err.Error(), "toml: "))
	}
	for _, k := range md.Keys() {
		if config.SecretKey(k) {
			return nil, fmt.Errorf("key %q looks like a secret; the managed file holds no secrets", k.String())
		}
	}
	sum := sha256.Sum256(data)
	f := &File{Fingerprint: hex.EncodeToString(sum[:]), tools: map[string]any{}}
	switch v, ok := raw["version"].(int64); {
	case !ok:
		return nil, fmt.Errorf("version = %d is required", Version)
	case v != Version:
		return nil, fmt.Errorf("version %d is not supported (this build reads version %d)", v, Version)
	}
	for _, key := range slices.Sorted(maps.Keys(raw)) {
		val := raw[key]
		switch {
		case key == "version":
		case key == "organisation":
			s, ok := val.(string)
			if !ok || strings.IndexFunc(s, config.UnsafeRune) >= 0 || len(s) > 128 {
				return nil, errors.New("organisation must be a printable string of 128 bytes at most")
			}
			f.Organisation = s
		case key == "family":
			m, ok := val.(map[string]any)
			if !ok {
				return nil, errors.New("[family] must be a table")
			}
			if err := decodeTable(m, &f.Family); err != nil {
				return nil, fmt.Errorf("[family]: %w", err)
			}
		case slices.Contains(lockTools, key):
			m, ok := val.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("[%s] must be a table", key)
			}
			if err := checkLockSection(key, m); err != nil {
				return nil, err
			}
			f.tools[key] = m
		case slices.Contains(wholeTools, key):
			m, ok := val.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("[%s] must be a table", key)
			}
			f.tools[key] = m
		default:
			return nil, fmt.Errorf("unknown key %q", key)
		}
	}
	return f, nil
}

func checkLockSection(tool string, m map[string]any) error {
	for _, kind := range slices.Sorted(maps.Keys(m)) {
		if kind != KindBounds && kind != KindDefaults && kind != KindProfiles {
			return fmt.Errorf("unknown key %q", tool+"."+kind)
		}
		t, ok := m[kind].(map[string]any)
		if !ok {
			return fmt.Errorf("[%s.%s] must be a table", tool, kind)
		}
		if kind != KindProfiles {
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(t)) {
			if _, ok := t[name].(map[string]any); !ok {
				return fmt.Errorf("[%s.profiles.%s] must be a table", tool, name)
			}
			if err := config.CheckProfileName(name, false); err != nil {
				return fmt.Errorf("[%s.profiles]: %w", tool, err)
			}
		}
	}
	return nil
}

// Source reads the managed file at one path, re-verifying the signature
// only when the file, its signature or the signer identity change.
type Source struct {
	path string
	// skipOwner disables the ownership check (test builds only).
	skipOwner bool
	owner     func(fs.FileInfo) (uid uint32, ok bool)
	verify    func(ctx context.Context, artifact, bundle []byte, id update.Identity) error

	mu       sync.Mutex
	cacheKey [sha256.Size]byte
	cached   *File
}

func newSource(path string) *Source {
	return &Source{path: path, owner: fileOwner, verify: func(ctx context.Context, a, b []byte, id update.Identity) error {
		return update.Verify(ctx, a, b, id, update.Options{})
	}}
}

// std is the machine's managed file.
var std = newSource(DefaultPath())

// Load reads the machine's managed file. It returns nil and no error when
// there is none. Any other failure (a badly owned file or directory, an
// invalid file, a signature that does not verify or is missing when
// required) is an error: the caller refuses to start, or ends its session.
func Load(ctx context.Context) (*File, error) { return std.Load(ctx) }

// Load reads the managed file of s (see the package Load).
func (s *Source) Load(ctx context.Context) (*File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return nil, nil
	}
	data, ok, err := s.read(s.path)
	if err != nil || !ok {
		return nil, err
	}
	dir := filepath.Dir(s.path)
	bundle, signed, err := s.readPlain(filepath.Join(dir, BundleName))
	if err != nil {
		return nil, err
	}
	var signer []byte
	if signed {
		var found bool
		if signer, found, err = s.read(filepath.Join(dir, SignerName)); err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("managed: %s is signed but %s, the company identity to check it against, is missing", s.path, filepath.Join(dir, SignerName))
		}
	}
	h := sha256.New()
	for _, b := range [][]byte{data, bundle, signer} {
		fmt.Fprintf(h, "%d:", len(b))
		h.Write(b)
	}
	var key [sha256.Size]byte
	copy(key[:], h.Sum(nil))
	if s.cached != nil && key == s.cacheKey {
		return s.cached, nil
	}
	f, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("managed: %s: %w", s.path, err)
	}
	f.Path = s.path
	switch {
	case signed:
		id, err := parseSigner(signer)
		if err != nil {
			return nil, fmt.Errorf("managed: %s: %w", filepath.Join(dir, SignerName), err)
		}
		if err := s.verify(ctx, data, bundle, id); err != nil {
			return nil, fmt.Errorf("managed: %s: the signature does not verify: %w", s.path, err)
		}
		f.Signed = true
	case f.Family.RequireSignature:
		return nil, fmt.Errorf("managed: %s: [family] require_signature is set but %s is missing", s.path, BundleName)
	}
	s.cacheKey, s.cached = key, f
	return f, nil
}

// read reads a root-owned file: false and no error when it does not exist.
func (s *Source) read(path string) ([]byte, bool, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("managed: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("managed: %s is not a regular file", path)
	}
	if err := s.checkOwned(path, fi); err != nil {
		return nil, false, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("managed: %w", err)
	}
	return b, true, nil
}

// readPlain reads a regular file whose content is verified, not trusted
// (the signature bundle): false and no error when it does not exist.
func (s *Source) readPlain(path string) ([]byte, bool, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("managed: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("managed: %s is not a regular file", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("managed: %w", err)
	}
	return b, true, nil
}

// checkOwned refuses a file, or its directory, that someone other than
// root could change.
func (s *Source) checkOwned(path string, fi fs.FileInfo) error {
	if s.skipOwner {
		return nil
	}
	for _, p := range []string{path, filepath.Dir(path)} {
		info := fi
		if p != path {
			var err error
			if info, err = os.Stat(p); err != nil {
				return fmt.Errorf("managed: %w", err)
			}
		}
		uid, ok := s.owner(info)
		if !ok {
			return fmt.Errorf("managed: cannot read the owner of %s", p)
		}
		if uid != 0 {
			return fmt.Errorf("managed: %s must be owned by root (it is owned by uid %d)", p, uid)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("managed: %s must be writable by root only (mode %04o)", p, info.Mode().Perm())
		}
	}
	return nil
}

// signer is signer.toml: the identity the managed file's signature is
// checked against.
type signer struct {
	CertIdentityRegexp string `toml:"certificate_identity_regexp"`
	OIDCIssuer         string `toml:"oidc_issuer"`
}

func parseSigner(b []byte) (update.Identity, error) {
	var s signer
	md, err := toml.Decode(string(b), &s)
	if err != nil {
		return update.Identity{}, errors.New("invalid TOML")
	}
	if und := md.Undecoded(); len(und) > 0 {
		return update.Identity{}, fmt.Errorf("unknown key %q", und[0].String())
	}
	if !strings.HasPrefix(s.CertIdentityRegexp, "^https://") || !strings.HasPrefix(s.OIDCIssuer, "https://") {
		return update.Identity{}, errors.New("certificate_identity_regexp must be an anchored ^https:// regexp and oidc_issuer an https:// URL")
	}
	return update.Identity{CertIdentityRegexp: s.CertIdentityRegexp, OIDCIssuer: s.OIDCIssuer}, nil
}
