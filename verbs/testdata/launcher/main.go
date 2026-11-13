// Command launcher is a tiny `profile add` built the way GUIDE §14 shows,
// for the end-to-end test of verbs: its arguments are those of
// `profile add` after the verb.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/verbs"
)

var P = kit.Product{Name: "lockmq", Account: "lockmq", ClientsGroup: "lockmq-clients", KeychainService: "lockmq", EnvPrefix: "LOCKMQ_"}

func main() {
	args := os.Args[1:]
	fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
	fs.Bool(verbs.FlagNonInteractive, false, "never read the terminal")
	fs.Bool(verbs.FlagJSON, false, "print one line of JSON")
	profile := fs.String(verbs.FlagProfile, "dev", "the profile name")
	production := fs.Bool(verbs.FlagProduction, false, "a production profile")
	credentials := fs.String(verbs.FlagCredentials, "", "ask or vault")
	vaultPath := fs.String(verbs.FlagVaultPath, "", "the Vault path")
	fs.String("url", "", "the management API")
	fs.String("user", "", "the user")

	asJSON := verbs.WantsJSON(args)
	fail := func(err error, code string) {
		if asJSON {
			_ = verbs.WriteJSON(os.Stdout, verbs.Error{Lock: P.Name, Code: verbs.ErrorCode(err, code), Error: err.Error()})
		} else {
			fmt.Fprintln(os.Stderr, "lockmq: "+err.Error())
		}
		os.Exit(2)
	}
	if err := verbs.Parse(P, fs, args); errors.Is(err, flag.ErrHelp) {
		fs.SetOutput(os.Stderr)
		fs.Usage()
		os.Exit(0)
	} else if err != nil {
		fail(err, verbs.CodeUsage)
	}
	cred, err := verbs.Credentials(*credentials, *vaultPath)
	if err != nil {
		fail(err, verbs.CodeUsage)
	}
	out := verbs.Profile{Lock: P.Name, Profile: *profile, Config: "/p/.lockmq/config.toml", Production: *production, Credentials: cred}
	if asJSON {
		_ = verbs.WriteJSON(os.Stdout, out)
		return
	}
	fmt.Fprintf(os.Stderr, "added profile %s\n", *profile)
}
