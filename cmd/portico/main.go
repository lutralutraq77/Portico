// Command portico reports development build information.
// It does not start any network service.
package main

import (
	"os"

	"portico.local/portico/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
