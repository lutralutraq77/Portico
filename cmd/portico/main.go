// Command portico provides development client/connector commands and build
// information. Deployment and service installation remain separate gates.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"portico.local/portico/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.RunInputContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
