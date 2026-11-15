package mdns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/forkcloser/go-mdns/internal/engine"
	"github.com/forkcloser/go-mdns/internal/wire"
)

// numbered is the numbering RFC 6762 section 9 suggests for a name that
// is taken: "name-2", "name-3" for a host, "Name (2)", "Name (3)" for a
// service. taken is the name refused, tries how many were so far.
func numbered(taken string, tries int, host bool) string {
	before, after := " (", ")"
	if host {
		before, after = "-", ""
	}

	// The number the last try put there goes, and the next takes its
	// place.
	base := strings.TrimSuffix(taken, fmt.Sprintf("%s%d%s", before, tries, after))
	suffix := fmt.Sprintf("%s%d%s", before, tries+1, after)

	for len(base)+len(suffix) > maxLabel {
		_, size := utf8.DecodeLastRuneInString(base)
		base = base[:len(base)-size]
	}

	return base + suffix
}

// rename asks what name to take in place of one that is taken, and says
// no for a name that cannot be one.
func rename(asked Rename, taken string, tries int, host bool) (string, bool) {
	if asked == nil {
		return numbered(taken, tries, host), true
	}

	next, ok := asked(taken, tries)
	if !ok {
		return "", false
	}

	if host {
		if named, err := hostName(next); err != nil || len(named) != len(Name{"host", local}) {
			return "", false
		}

		return strings.TrimSuffix(strings.TrimSuffix(next, "."), "."+local), true
	}

	return next, instanceLabel(next) == nil
}

// systemHost is the name the system gives the host, as one label; and
// "host" for a system that gives none that can be one.
func systemHost() string {
	name, err := os.Hostname()
	if err == nil {
		name, _, _ = strings.Cut(name, ".")
	}

	if _, err = hostName(name); err != nil || name == "" {
		return "host"
	}

	return name
}

// claim is the host's name, held on the network.
type claim struct {
	label string
	// refused is how many names were refused before this one.
	refused   int
	published *engine.Publication
}

// host is the name the host holds, claimed now if it was not yet: asked
// for on every link, and another tried when it is taken.
func (p *Peer) host(ctx context.Context) (Name, error) {
	p.claiming.Lock()
	defer p.claiming.Unlock()

	p.mu.Lock()
	held := p.held
	p.mu.Unlock()

	if held != nil {
		return Name{held.label, local}, nil
	}

	held, err := p.claim(ctx, p.wanted, 0)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.held = held
	p.mu.Unlock()

	p.keeping.Go(func() { p.keepHost(held) })

	return Name{held.label, local}, nil
}

// claim publishes the host's addresses under a name, and under the next
// that Rename gives for as long as the one tried is taken.
func (p *Peer) claim(ctx context.Context, label string, refused int) (*claim, error) {
	for tries := refused + 1; ; tries++ {
		published, err := p.engine.Publish(ctx, engine.Set{Host: []string{label, local}, Addresses: p.addresses})
		if err == nil {
			return &claim{label: label, refused: tries - 1, published: published}, nil
		}

		if !errors.Is(err, engine.ErrConflict) {
			return nil, translate(err)
		}

		next, ok := rename(p.rename, label, tries, true)
		if !ok {
			return nil, fmt.Errorf("%w: the host name %q", ErrConflict, label)
		}

		label = next
	}
}

// keepHost takes another name when a host turns up with this one's, and
// points every service at it; and ends them all when no name is to be
// had.
func (p *Peer) keepHost(held *claim) {
	for {
		<-held.published.Done()

		if !errors.Is(held.published.Err(), engine.ErrConflict) {
			return
		}

		held = p.reclaim(held)

		p.mu.Lock()
		p.held = held
		announced := slices.Clone(p.announced)
		p.mu.Unlock()

		for _, service := range announced {
			switch {
			case service.elsewhere != nil:
			case held == nil:
				service.end(ErrConflict)
			default:
				service.retarget(Name{held.label, local})
			}
		}

		if held == nil {
			return
		}
	}
}

// reclaim holds the host under the name Rename gives for one that was
// lost; and holds nothing when it gives none, or the Peer is closing.
func (p *Peer) reclaim(lost *claim) *claim {
	next, ok := rename(p.rename, lost.label, lost.refused+1, true)
	if !ok {
		return nil
	}

	p.claiming.Lock()
	defer p.claiming.Unlock()

	held, err := p.claim(p.life, next, lost.refused+1)
	if err != nil {
		return nil
	}

	return held
}

// elsewhere is a host that is not this one, announced on its behalf.
type elsewhere struct {
	key       string
	addrs     []wire.Record
	published *engine.Publication
	users     int
}

// borrow announces a host that is not this one, at the addresses given,
// for one more service; or again, when it already is.
func (p *Peer) borrow(ctx context.Context, service *Service) (*elsewhere, Name, error) {
	host, err := hostName(service.Host)
	if err != nil {
		return nil, nil, err
	}

	var addrs []wire.Record

	for _, addr := range service.Addrs {
		addrs = append(addrs, wire.Record{
			Name: host, TTL: ttlOf(service.TTL, hostTTL), Flush: true, Data: wire.Address{Addr: addr.WithZone("")},
		})
	}

	p.claiming.Lock()
	defer p.claiming.Unlock()

	p.mu.Lock()
	known := p.others[host.key()]
	p.mu.Unlock()

	if known == nil {
		published, err := p.engine.Publish(ctx, engine.Set{Records: addrs, Interfaces: service.Interfaces})
		if err != nil {
			return nil, nil, translate(err)
		}

		known = &elsewhere{key: host.key(), addrs: addrs, published: published}
	} else if !sameAddresses(known.addrs, addrs) {
		return nil, nil, fmt.Errorf("%w: %q is already announced at other addresses", ErrInvalid, service.Host)
	}

	p.mu.Lock()
	known.users++
	p.others[known.key] = known
	p.mu.Unlock()

	return known, host, nil
}

// give gives back a host that was announced for a service.
func (p *Peer) give(borrowed *elsewhere) {
	p.mu.Lock()
	borrowed.users--

	last := borrowed.users == 0
	if last {
		delete(p.others, borrowed.key)
	}
	p.mu.Unlock()

	if last {
		_ = borrowed.published.Close()
	}
}

func sameAddresses(one, other []wire.Record) bool {
	if len(one) != len(other) {
		return false
	}

	for index := range one {
		if one[index].Data != other[index].Data {
			return false
		}
	}

	return true
}

// key is a name as names are compared: without the case of its ASCII
// letters.
func (n Name) key() string {
	return strings.Map(func(char rune) rune {
		if char >= 'A' && char <= 'Z' {
			return char + ('a' - 'A')
		}

		return char
	}, n.String())
}
