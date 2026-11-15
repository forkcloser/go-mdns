// Package mdns is Multicast DNS (RFC 6762) and DNS-Based Service
// Discovery (RFC 6763): announcing what a host offers on the links it is
// on, and finding what its neighbours offer.
//
// A Peer is a host's part in it. It asks and it answers, over IPv4 and
// IPv6, on every interface the host has, and it is opened once: what it
// announces and what it looks for share its sockets and its memory of
// what it has heard, as the protocol means them to.
//
// There are three ways to use one, each built on the next:
//
//   - services: Announce one, Browse for those of a type, Resolve one by
//     name;
//   - hosts: every Peer that announces answers for its host name, and
//     LookupHost finds another's addresses;
//   - records: Publish any record, Ask for any, which is all the other
//     two are made of.
//
// A Peer keeps what it hears on each link apart, as the protocol has
// it, and tells of it together: a printer seen on the wire and over the
// air is found once, and says both interfaces. What is announced goes
// to every interface, or to those chosen for it.
//
// What a Peer has to say that is no one's answer goes to log/slog's
// default logger, with the context it was said in.
package mdns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/transport"
)

// Family is IPv4 or IPv6.
type Family = transport.Family

// The families.
const (
	IPv4 = transport.IPv4
	IPv6 = transport.IPv6
)

// Interface names a network interface of the host.
type Interface = transport.Interface

// Config is what a Peer is opened with. The zero Config is a Peer on
// every interface of the host, over both families, under the host's own
// name.
type Config struct {
	// Hostname is the name the host answers to, with or without ".local":
	// what its services are reached at, and what LookupHost finds. Empty
	// is the system's own. It is claimed when something is first
	// announced, and not before: a Peer that only looks announces
	// nothing, its name included.
	Hostname string

	// Rename says what to do when another host already has the host
	// name. Nil numbers it.
	Rename Rename

	// Families is the families to speak: IPv4, IPv6, or both. Zero is
	// both.
	Families Family

	// Interfaces says which interfaces to be on, of those the network
	// has: On("en0"), or any rule. Nil is all of them. What is
	// announced and what is asked may each choose again, among these.
	Interfaces func(Interface) bool

	// Addresses says which of an interface's own addresses the host is
	// announced at on that interface. Nil is all of them. An address is
	// only ever announced on the interface it belongs to.
	Addresses func(Interface, netip.Addr) bool

	// Network is where the links are. Nil is transport.System, the
	// host's own.
	Network transport.Network
}

// Rename is asked what name to take when the one wanted is another's:
// taken is that name, and tries how many have been refused so far, from
// one. It answers the next to try, or false to give up, which ends what
// was being announced with ErrConflict. It is asked when a name is first
// claimed and whenever a host turns up later with the same one, so it is
// also how a program learns that it was renamed.
//
// Nil, wherever a Rename is taken, is the numbering RFC 6762 suggests: a
// service "Name" becomes "Name (2)", then "Name (3)"; a host "name"
// becomes "name-2", then "name-3". It never gives up.
type Rename func(taken string, tries int) (next string, ok bool)

// Never is the Rename that gives up at once: the name asked for, or
// none.
func Never(string, int) (string, bool) { return "", false }

// Peer is a host's part in Multicast DNS: its responder and its querier,
// on every link it is on. Its methods may be called from several
// goroutines.
type Peer struct {
	engine *engine.Engine
	// rename and addresses are the configuration's, for the host's
	// name; wanted is the name asked for, as one label.
	rename    Rename
	addresses func(Interface, netip.Addr) bool
	wanted    string
	// life ends when the Peer closes, and keeping is what it started
	// that ends with it.
	life    context.Context //nolint:containedctx // what outlives a call: a name taken again after it was lost
	stop    context.CancelFunc
	keeping sync.WaitGroup

	// claiming is held while a host's name is asked for, so that one is
	// asked for at a time.
	claiming sync.Mutex
	// mu guards what follows: the name held, the hosts announced for
	// others, and the services announced.
	mu        sync.Mutex
	held      *claim
	others    map[string]*elsewhere
	announced []*Announcement
}

// Open makes a Peer and puts it on the network: when it returns, every
// other method works. ctx bounds the opening alone. A host with no
// usable interface is no error: links are taken up as they come, and
// given up as they go, for as long as the Peer is open.
func Open(ctx context.Context, cfg Config) (*Peer, error) {
	wanted := systemHost()

	if cfg.Hostname != "" {
		named, err := hostName(cfg.Hostname)
		if err != nil {
			return nil, err
		}

		if len(named) != len(Name{wanted, local}) {
			return nil, fmt.Errorf("%w: the host name %q is more than one label under local", ErrInvalid, cfg.Hostname)
		}

		wanted = named[0]
	}

	network := cfg.Network
	if network == nil {
		network = transport.System()
	}

	opened, err := engine.Open(ctx, engine.Config{Network: network, Families: cfg.Families, Interfaces: cfg.Interfaces})
	if err != nil {
		return nil, translate(err)
	}

	life, stop := context.WithCancel(context.WithoutCancel(ctx))

	return &Peer{
		engine: opened, rename: cfg.Rename, addresses: cfg.Addresses, wanted: wanted,
		life: life, stop: stop, others: map[string]*elsewhere{},
	}, nil
}

// Close says goodbye for everything the Peer announces, leaves the
// network, and returns when everything it started has ended. After it,
// every call that returns an error returns ErrClosed, and every Browse
// and Ask in flight ends with it.
func (p *Peer) Close() error {
	p.stop()

	err := p.engine.Close()
	p.keeping.Wait()

	return translate(err)
}

// translate says an engine's error in this package's words.
func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, engine.ErrClosed):
		return ErrClosed
	case errors.Is(err, engine.ErrConflict):
		return ErrConflict
	case errors.Is(err, engine.ErrInvalid):
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	default:
		return err
	}
}

// Hostname is the name the host answers to now, ending in ".local": the
// one asked for, or the one it was renamed to. Before anything is
// announced it is the name that will be claimed.
func (p *Peer) Hostname() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.held != nil {
		return Name{p.held.label, local}.String()
	}

	return Name{p.wanted, local}.String()
}

// On chooses interfaces by name, for the fields that take a choice of
// interfaces: On("en0", "en1"). With no name it chooses none.
func On(names ...string) func(Interface) bool {
	return func(candidate Interface) bool {
		return slices.Contains(names, candidate.Name)
	}
}
