package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/DavidGodefroid/lockkit/kit"
)

var stateKeyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// ApprovedKey names the approved-policy file of a profile:
// <ProjectHash(root)>-<profile>, or user-<profile> for a profile that comes
// from the user config only (root == "").
func ApprovedKey(root, profile string) string {
	if root == "" {
		return "user-" + profile
	}
	return ProjectHash(root) + "-" + profile
}

// ApprovedPath is <stateDir>/<p.Name>/approved/<key>.json.
func ApprovedPath(p kit.Product, stateDir, key string) (string, error) {
	if !stateKeyRe.MatchString(key) {
		return "", fmt.Errorf("config: invalid approved-policy key %q", key)
	}
	return filepath.Join(stateDir, p.Name, "approved", key+".json"), nil
}

// LoadApproved decodes the approved policy of key into into. It returns
// false and no error when no policy was approved yet.
func LoadApproved(p kit.Product, stateDir, key string, into any) (bool, error) {
	path, err := ApprovedPath(p, stateDir, key)
	if err != nil {
		return false, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("config: approved policy: %w", err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		return false, fmt.Errorf("config: approved policy %s: %w", path, err)
	}
	return true, nil
}

// SaveApproved atomically writes v, indented JSON with a final newline,
// as the approved policy of key, mode 0600 in a 0700 directory.
func SaveApproved(p kit.Product, stateDir, key string, v any) error {
	path, err := ApprovedPath(p, stateDir, key)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+key+".*.tmp")
	if err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("config: approved policy: %w", err)
	}
	ok = true
	return nil
}
