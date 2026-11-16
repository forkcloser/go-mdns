// The mdns command announces services on the local network for programs
// that cannot speak Multicast DNS themselves, and looks for services by
// hand. Run it with no argument for how.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/forkcloser/go-mdns/internal/command"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	code := command.Run(ctx, command.Environment{
		Args: os.Args[1:], In: os.Stdin, Out: os.Stdout, Err: os.Stderr,
	})

	stop()
	os.Exit(code)
}
