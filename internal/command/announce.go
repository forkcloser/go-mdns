package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/forkcloser/go-mdns"
)

// announcing is the services the command announces.
type announcing struct {
	env  *Environment
	peer *mdns.Peer
	// lost is told when a service is lost to another host and may take
	// no other name: the command then leaves.
	lost    chan error
	keeping sync.WaitGroup
}

// announce announces services until it is told to stop, or one of them
// is lost for good. Told to stop, it has done what it was asked, however
// far it had come.
func announce(ctx context.Context, env *Environment, args []string) error {
	err := announceAll(ctx, env, args)
	if ctx.Err() != nil && errors.Is(err, context.Cause(ctx)) {
		return nil
	}

	return err
}

// announceAll announces the services it is asked to, and returns when
// ctx ends or one of them is lost for good.
func announceAll(ctx context.Context, env *Environment, args []string) error {
	from, err := announced(args)
	if err != nil {
		return err
	}

	want, err := from.load(env)
	if err != nil {
		return err
	}

	peer, err := env.open(
		ctx,
		mdns.Config{Hostname: want.hostname, Rename: func(taken string, tries int) (string, bool) {
			next := numbered(taken, tries, "-", "")
			env.say(said{Event: "host", Name: next + ".local", Asked: want.hostname})

			return next, true
		}},
	)
	if err != nil {
		return err
	}

	state := &announcing{env: env, peer: peer, lost: make(chan error, 1)}

	// Goodbye is said for everything on the way out, whatever the way.
	defer state.keeping.Wait()
	defer func() { _ = peer.Close() }()

	for _, one := range want.services {
		if err = state.start(ctx, one); err != nil {
			return err
		}
	}

	select {
	case <-ctx.Done():
		return nil
	case err = <-state.lost:
		return err
	}
}

// announced reads the arguments of announce: a document, or flags that
// say one service.
func announced(args []string) (*source, error) {
	var (
		set        = flags("announce")
		one        service
		port       = set.Uint("port", 0, "")
		ttl        = set.Duration("ttl", 0, "")
		fixed      = set.Bool("no-rename", false, "")
		hostname   = set.String("hostname", "", "")
		text, addr list
	)

	set.StringVar(&one.Name, "name", "", "")
	set.StringVar(&one.Type, "type", "", "")
	set.StringVar(&one.Host, "host", "", "")
	set.Var(&text, "txt", "")
	set.Var(&addr, "address", "")
	set.Var((*list)(&one.Subtypes), "subtype", "")
	set.Var((*list)(&one.Interfaces), "interface", "")

	const usage = "announce FILE, or announce --type TYPE --port PORT [...]"

	if err := set.Parse(args); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errUsage, usage, err)
	}

	given := map[string]bool{}

	set.Visit(func(flag *flag.Flag) { given[flag.Name] = true })

	// A document, and nothing else; or a type and a port, and no document.
	switch {
	case set.NArg() == 1 && len(given) == 0:
		return &source{path: set.Arg(0)}, nil
	case set.NArg() != 0 || !given["type"] || !given["port"] || *port > maxPort:
		return nil, fmt.Errorf("%w: %s", errUsage, usage)
	}

	number := uint16(*port) // #nosec G115 -- at most maxPort, by the check above
	one.Port, one.TTL, one.Rename = &number, duration(*ttl), new(!*fixed)

	for _, written := range text {
		key, value, valued := strings.Cut(written, "=")
		one.Text = append(one.Text, entry{Key: key})

		if valued {
			one.Text[len(one.Text)-1].Value = []byte(value)
		}
	}

	for _, written := range addr {
		parsed, err := netip.ParseAddr(written)
		if err != nil {
			return nil, fmt.Errorf("%w: the address %q: %w", errUsage, written, err)
		}

		one.Addresses = append(one.Addresses, parsed)
	}

	service := one.announced()
	if err := service.service.Validate(); err != nil {
		return nil, fmt.Errorf("the service: %w", err)
	}

	return &source{once: wanted{hostname: *hostname, services: []asked{service}}}, nil
}

// maxPort is the highest port there is.
const maxPort = 1<<16 - 1

// start announces one service, and watches for the day it is lost.
func (a *announcing) start(ctx context.Context, one asked) error {
	service := one.service
	service.Rename = mdns.Never

	if one.rename {
		service.Rename = func(taken string, tries int) (string, bool) {
			next := numbered(taken, tries, " (", ")")
			a.env.say(said{Event: "renamed", Name: next, Asked: one.service.Name, Type: one.service.Type})

			return next, true
		}
	}

	announced, err := a.peer.Announce(ctx, service)
	if err != nil {
		return fmt.Errorf("the service %q of type %s: %w", one.service.Name, one.service.Type, err)
	}

	a.env.say(
		said{
			Event: "announced",
			Name:  announced.Name(),
			Asked: one.service.Name,
			Type:  one.service.Type,
			Host:  a.host(&one.service),
		},
	)

	a.keeping.Go(func() {
		<-announced.Done()

		// Withdrawn by the command itself, or by its end: nothing to say.
		if !errors.Is(announced.Err(), mdns.ErrConflict) {
			return
		}

		a.env.say(said{Event: "lost", Name: announced.Name(), Asked: one.service.Name, Type: one.service.Type})

		select {
		case a.lost <- fmt.Errorf("the service %q of type %s: %w", announced.Name(), one.service.Type, announced.Err()):
		default:
		}
	})

	return nil
}

// host is the host a service is announced on, as it is said: this one,
// or the one the service says it is on, under "local" as this one is.
func (a *announcing) host(service *mdns.Service) string {
	if service.Host == "" {
		return a.peer.Hostname()
	}

	// A name, or the service would not have been announced.
	name, _ := mdns.ParseName(service.Host)
	if len(name) == 0 || !strings.EqualFold(name[len(name)-1], "local") {
		name = append(name, "local")
	}

	return name.String()
}

// numbered is the name to take in place of one that is taken, as RFC
// 6762 section 9 suggests: the next number after it, in place of the
// last when there was one.
func numbered(taken string, tries int, before, after string) string {
	base := strings.TrimSuffix(taken, fmt.Sprintf("%s%d%s", before, tries, after))
	suffix := fmt.Sprintf("%s%d%s", before, tries+1, after)

	for len(base)+len(suffix) > maxLabel {
		_, size := utf8.DecodeLastRuneInString(base)
		base = base[:len(base)-size]
	}

	return base + suffix
}

// maxLabel is the most bytes a name holds.
const maxLabel = 63
