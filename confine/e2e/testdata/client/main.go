// Command client is the e2e test's lock client: it dials the console of
// profile uat through package client (whose hello carries the real
// confine.Check of where it runs) and prints the outcome as JSON.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/DavidGodefroid/lockkit/client"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/kit"
)

func main() {
	p := kit.Product{Name: "locke2e", Account: "locke2e", ClientsGroup: "locke2e-clients", KeychainService: "locke2e", EnvPrefix: "LOCKE2E_"}
	out := map[string]any{}
	c, err := client.Dial(p, "/", "uat")
	if err == nil {
		defer c.Close()
		err = c.Call(context.Background(), ipc.MethodStatus, nil, nil)
	}
	var re *ipc.RPCError
	switch {
	case err == nil:
		out["served"] = true
	case errors.As(err, &re):
		out["code"], out["message"] = re.Code, re.Message
	default:
		out["error"] = err.Error()
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
	os.Exit(0)
}
