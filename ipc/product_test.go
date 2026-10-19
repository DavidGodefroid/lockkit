package ipc

import "github.com/DavidGodefroid/lockkit/kit"

var testProduct = kit.Product{Name: "locksql", Account: "locksql", ClientsGroup: "locksql-clients",
	KeychainService: "locksql", EnvPrefix: "LOCKSQL_"}
