package client

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/DavidGodefroid/lockkit/kit"
)

// FlagInstance is the flag a product's client commands and MCP server
// take to pick one lock among several of its type (--instance NAME).
const FlagInstance = "instance"

// ErrBadInstance is the refusal of an instance name that is not a lock
// instance name. Its errors name where the name came from, never the name.
var ErrBadInstance = errors.New("not a lock instance name")

// instanceRe is lox's rule for instance names.
var instanceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// CheckInstance checks name against lox's rule for instance names:
// lowercase letters, digits and '-', starting with a letter or digit, at
// most 63 characters. Such a name is one path element.
func CheckInstance(name string) error {
	if !instanceRe.MatchString(name) {
		return ErrBadInstance
	}
	return nil
}

// InstanceEnv is the environment variable that picks p's instance when no
// flag does ("LOCKSQL_INSTANCE").
func InstanceEnv(p kit.Product) string { return p.Env("INSTANCE") }

// InstancesEnv is the variable lea sets in the agent's container when it
// mounts several locks of p's type, each on <shared socket dir>/<instance>:
// their names, space separated ("LEA_LOCKSQL_INSTANCES").
func InstancesEnv(p kit.Product) string { return "LEA_" + p.Env("INSTANCES") }

// ResolveInstance is the lock instance the client reaches: flag (the
// value of --instance) when set, else $<PREFIX>INSTANCE, else the one
// name InstancesEnv lists. It is "" when none is set and InstancesEnv is
// empty: the client reaches the socket directory itself, as before
// instances. When InstancesEnv lists names, the instance must be one of
// them, and one must be chosen when it lists several. Every name is
// checked (CheckInstance) before it is used.
func ResolveInstance(p kit.Product, flag string) (string, error) {
	listEnv, env := InstancesEnv(p), InstanceEnv(p)
	list := strings.Fields(os.Getenv(listEnv))
	for _, n := range list {
		if CheckInstance(n) != nil {
			return "", fmt.Errorf("%s: %w", listEnv, ErrBadInstance)
		}
	}
	name, from := flag, "--"+FlagInstance
	if name == "" {
		name, from = os.Getenv(env), env
	}
	if name == "" {
		switch len(list) {
		case 0:
			return "", nil
		case 1:
			return list[0], nil
		}
		return "", fmt.Errorf("several %s locks: %s; pass --%s NAME (or set %s)", p.Name, strings.Join(list, " "), FlagInstance, env)
	}
	if CheckInstance(name) != nil {
		return "", fmt.Errorf("%s: %w", from, ErrBadInstance)
	}
	if len(list) > 0 && !slices.Contains(list, name) {
		return "", fmt.Errorf("no %s lock %s: %s", p.Name, name, strings.Join(list, " "))
	}
	return name, nil
}
