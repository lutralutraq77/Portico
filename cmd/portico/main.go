// Command portico provides development build information and the isolated Linux
// connector runtime. Deployment and service installation remain separate gates.
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
	code := cli.RunContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
