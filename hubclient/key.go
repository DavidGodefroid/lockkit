package hubclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// instanceRE is the name of a lock instance, as lockhub (keys.ValidInstance)
// and lockfamily.yaml take it: also a file name.
var instanceRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidInstance reports whether name is a valid lock instance name.
func ValidInstance(name string) bool { return instanceRE.MatchString(name) }

// KeyDir is where a lock keeps its instance keys, under its home volume.
func KeyDir(home string) string { return filepath.Join(home, "hub") }

// homeDir is home, or the user's home when empty: never the working
// directory.
func homeDir(home string) (string, error) {
	if home != "" {
		return home, nil
	}
	h, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(h) {
		return "", fmt.Errorf("hubclient: no home directory for the instance key (%v)", err)
	}
	return h, nil
}

// InstanceKey returns the Ed25519 key of instance, kept in
// KeyDir(home)/<instance>.key (0600 in a 0700 directory, the seed in
// base64 std on one line); home "" is the user's home. The first call
// creates it; a key file group or others can read is refused.
func InstanceKey(home, instance string) (ed25519.PrivateKey, error) {
	if !ValidInstance(instance) {
		return nil, fmt.Errorf("hubclient: invalid instance name %q", instance)
	}
	home, err := homeDir(home)
	if err != nil {
		return nil, err
	}
	dir := KeyDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("hubclient: %w", err)
	}
	path := filepath.Join(dir, instance+".key")
	b, err := readPrivate(path)
	if errors.Is(err, os.ErrNotExist) {
		return createKey(path)
	} else if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("hubclient: %s is not an instance key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// readPrivate reads a regular file no one but its owner can open: not a
// symlink, and checked on the descriptor it is read through.
func readPrivate(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("hubclient: %s is not a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|nonBlock, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err = f.Stat(); err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("hubclient: %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("hubclient: %s is open to group or others (%v)", path, fi.Mode().Perm())
	}
	return io.ReadAll(io.LimitReader(f, 1024))
}

func createKey(path string) (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("hubclient: %w", err)
	}
	_, werr := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("hubclient: %w", err)
	}
	return priv, nil
}

// ReadHubKey reads the pinned hub key: an Ed25519 public key in base64 std
// on one line (the file `lock up` mounts at /run/lockfamily/hub.pub).
func ReadHubKey(path string) (ed25519.PublicKey, error) {
	b, err := readSmallRegular(path, 1024)
	if err != nil {
		return nil, fmt.Errorf("hubclient: hub key: %w", err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	pub, err := base64.StdEncoding.DecodeString(s)
	if err != nil || strings.ContainsAny(s, "\r\n") || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("hubclient: %s is not an Ed25519 public key in base64 on one line", path)
	}
	return ed25519.PublicKey(pub), nil
}

// readSmallRegular reads path, a regular file of at most max bytes,
// through one descriptor opened without waiting: a FIFO, a device or a
// directory is refused, never read.
func readSmallRegular(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|nonBlock, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return b, nil
}

// HubKeyCommand is a lock's `hub-key --instance NAME`: it prints the
// public key of the instance (InstanceKey of home, "" the user's, created
// on the first call) in
// base64 std on one line, for `lock up` to pin at the hub.
func HubKeyCommand(w io.Writer, home string, args []string) error {
	fs := flag.NewFlagSet("hub-key", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	inst := fs.String("instance", "", "the lock instance name")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("usage: hub-key --instance NAME: %w", err)
	}
	if fs.NArg() != 0 || *inst == "" {
		return errors.New("usage: hub-key --instance NAME")
	}
	k, err := InstanceKey(home, *inst)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)))
	return err
}

// ReadDevices reads the pinned approval devices: a ticket.DeviceSet (the
// file `lock up` mounts at /run/lockfamily/devices.json, written from the
// devices the human confirmed at the host's terminal).
func ReadDevices(path string) ([]ticket.Device, error) {
	b, err := readSmallRegular(path, 64<<10)
	if err != nil {
		return nil, fmt.Errorf("hubclient: devices: %w", err)
	}
	devs, err := ticket.ParseDevices(b)
	if err != nil {
		return nil, fmt.Errorf("hubclient: %s: %w", path, err)
	}
	return devs, nil
}

// ParseRisks reads a comma-separated list of risk classes ("" is none),
// as --require-device takes it.
func ParseRisks(s string) ([]ticket.Risk, error) {
	if s == "" {
		return nil, nil
	}
	var out []ticket.Risk
	for _, f := range strings.Split(s, ",") {
		r, err := ticket.ParseRisk(strings.TrimSpace(f))
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
