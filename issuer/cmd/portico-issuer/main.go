package main

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	service "portico.local/portico/issuer"
)

func run(args []string, out io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(out, "portico-issuer 0.3.0-dev; restricted loopback development service")
		return 0
	}
	if len(args) == 0 || (args[0] != "serve" && args[0] != "result") {
		fmt.Fprintln(out, "usage: portico-issuer serve --config ABSOLUTE_PATH | result --config ABSOLUTE_PATH --attempt UUID | version")
		return 2
	}
	flags := flag.NewFlagSet("issuer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "absolute configuration path")
	attempt := flags.String("attempt", "", "local receipt lookup")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *path == "" || (args[0] == "serve" && *attempt != "") {
		return 2
	}
	config, address, e := service.LoadConfig(*path)
	if e != nil {
		fmt.Fprintln(out, "issuer configuration rejected")
		return 1
	}
	s, e := service.New(config)
	if e != nil {
		fmt.Fprintln(out, "issuer initialization rejected")
		return 1
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Close(ctx)
	}()
	if args[0] == "result" {
		r, e := s.Result(*attempt)
		if e != nil {
			fmt.Fprintln(out, "no verified receipt available; do not retry issuance")
			return 1
		}
		if pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: r.Certificate}) != nil {
			return 1
		}
		return 0
	}
	l, e := net.Listen("tcp", address)
	if e != nil {
		fmt.Fprintln(out, "issuer listener unavailable")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	go func() {
		<-ctx.Done()
		stop, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = s.Close(stop)
	}()
	if e = s.Serve(l); e != nil && !errors.Is(e, http.ErrServerClosed) {
		fmt.Fprintln(out, "issuer stopped unexpectedly")
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
