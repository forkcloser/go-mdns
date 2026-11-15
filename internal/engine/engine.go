// Package engine is a host's part in Multicast DNS (RFC 6762), at the
// level of records: it asks, remembers what it hears on each link for as
// long as it was told to, and tells of it. Package mdns is written on
// it, and says in its own words what this one does.
//
// Everything an Engine knows is one goroutine's, its loop's: what the
// links hear, what a caller asks and every timer come to it one at a
// time, so nothing in it is locked.
package engine

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/forkcloser/go-mdns/internal/wire"
	"github.com/forkcloser/go-mdns/transport"
)

// What can go wrong.
var (
	// ErrClosed is an Engine that is closed.
	ErrClosed = errors.New("closed")
	// ErrInvalid is a question or a record that cannot be said.
	ErrInvalid = errors.New("not valid in Multicast DNS")
)

// Config is how an Engine is opened.
type Config struct {
	// Network is where the links are.
	Network transport.Network
	// Families is the families to speak. Zero is both.
	Families transport.Family
	// Interfaces says which interfaces to be on. Nil is all of them.
	Interfaces func(transport.Interface) bool
}

// Engine is a host on its links.
type Engine struct {
	cfg  Config
	stop context.CancelFunc
	// settled is closed when the links there were at first are known;
	// quit is closed to end the loop, and done when it has ended.
	settled chan struct{}
	quit    chan struct{}
	done    chan struct{}
	calls   chan func()
	events  chan transport.Event
	packets chan arrival
	// running is the watch and the readers.
	running sync.WaitGroup
	closing sync.Once
	first   sync.Once

	// What follows is the loop's.
	now    time.Time
	timers timers
	links  map[transport.Link]*link
	asked  map[askKey]*asking
	named  map[string][]*asking
	sweep  *timer

	// pubs is what is published; seq orders its records; conflicts is
	// when names were lately lost.
	pubs      []*Publication
	seq       int
	conflicts []time.Time
}

// arrival is a message read from a link.
type arrival struct {
	link    transport.Link
	message wire.Message
	from    netip.AddrPort
	group   bool
}

// Open starts an Engine on a network, and returns once it knows the
// links there are. ctx bounds that wait alone: the Engine ends with
// Close.
func Open(ctx context.Context, cfg Config) (*Engine, error) {
	if cfg.Network == nil {
		return nil, fmt.Errorf("%w: no network to be on", ErrInvalid)
	}

	waiting := ctx

	ctx, stop := context.WithCancel(context.WithoutCancel(ctx))
	opened := &Engine{
		cfg:     cfg,
		stop:    stop,
		quit:    make(chan struct{}),
		settled: make(chan struct{}),
		done:    make(chan struct{}),
		calls:   make(chan func()),
		events:  make(chan transport.Event),
		packets: make(chan arrival),
		links:   map[transport.Link]*link{},
		asked:   map[askKey]*asking{},
		named:   map[string][]*asking{},
	}

	// Watch ends with the Engine, or sooner with why: before the links
	// were told of that is Open's to say, after it the log's. Which it
	// is goes by whether Settled was handed over, not by whether the
	// loop has taken it in yet: Open is on its way out by then.
	failed := make(chan error, 1)

	var told atomic.Bool

	opened.running.Go(func() {
		err := cfg.Network.Watch(ctx, func(event transport.Event) {
			select {
			case opened.events <- event:
				if event.Change == transport.Settled {
					told.Store(true)
				}
			case <-ctx.Done():
			}
		})
		if ctx.Err() != nil {
			return
		}

		if told.Load() {
			slog.ErrorContext(ctx, "the links can no longer be told of", "error", err)

			return
		}

		failed <- err
	})

	go opened.loop()

	// Not before the links are known: what is asked of the Engine first
	// is then asked on them, and not on none.
	select {
	case <-opened.settled:
		return opened, nil
	case err := <-failed:
		_ = opened.Close()

		return nil, fmt.Errorf("watching the network: %w", err)
	case <-waiting.Done():
		_ = opened.Close()

		return nil, fmt.Errorf("opening on the network: %w", context.Cause(waiting))
	}
}

// Close leaves the network and returns when everything the Engine
// started has ended. Everything asked of it afterwards is ErrClosed.
func (e *Engine) Close() error {
	// The loop first, while the links are still there to say goodbye on:
	// a network closes them when it is no longer watched.
	e.closing.Do(func() {
		close(e.quit)
		<-e.done
		e.stop()
		e.running.Wait()
	})

	return nil
}

// do runs something on the loop and waits for it.
func (e *Engine) do(run func()) error {
	finished := make(chan struct{})

	select {
	case e.calls <- func() { run(); close(finished) }:
		<-finished

		return nil
	case <-e.done:
		return ErrClosed
	}
}

// loop is the Engine: one thing at a time, and then every timer that is
// due.
func (e *Engine) loop() {
	defer close(e.done)

	wake := time.NewTimer(time.Hour)
	defer wake.Stop()

	for {
		e.now = time.Now()

		for len(e.timers) > 0 && !e.timers[0].at.After(e.now) {
			if due, ok := heap.Pop(&e.timers).(*timer); ok {
				due.run()
			}
		}

		// With nothing to wait for, nothing is waited for: an Engine
		// with nothing to do does not wake.
		var woken <-chan time.Time

		wake.Stop()

		if len(e.timers) > 0 {
			wake.Reset(e.timers[0].at.Sub(e.now))

			woken = wake.C
		}

		select {
		case <-e.quit:
			e.leave()

			return
		case event := <-e.events:
			e.now = time.Now()
			e.linked(event)
		case arrived := <-e.packets:
			e.now = time.Now()
			e.receive(arrived)
		case call := <-e.calls:
			e.now = time.Now()

			call()
		case <-woken:
		}
	}
}

// leave says goodbye for everything published, and closes the links,
// which ends their readers.
func (e *Engine) leave() {
	for _, published := range slices.Clone(e.pubs) {
		e.end(published, ErrClosed)
	}

	for _, left := range e.links {
		_ = left.wire.Close()
	}
}

// timer is something to do at a time.
type timer struct {
	at  time.Time
	run func()
	// index is where it is in the heap, and below zero when it is not.
	index int
}

// after does something in a while, on the loop.
func (e *Engine) after(wait time.Duration, run func()) *timer {
	return e.at(e.now.Add(wait), run)
}

func (e *Engine) at(when time.Time, run func()) *timer {
	set := &timer{at: when, run: run}
	heap.Push(&e.timers, set)

	return set
}

// cancel takes back a timer that has not run. One that has, or none, is
// left alone.
func (e *Engine) cancel(set *timer) {
	if set != nil && set.index >= 0 {
		heap.Remove(&e.timers, set.index)
	}
}

// timers is the timers to come, the soonest first.
type timers []*timer

func (t *timers) Len() int           { return len(*t) }
func (t *timers) Less(i, j int) bool { return (*t)[i].at.Before((*t)[j].at) }

func (t *timers) Swap(i, j int) {
	(*t)[i], (*t)[j] = (*t)[j], (*t)[i]
	(*t)[i].index, (*t)[j].index = i, j
}

func (t *timers) Push(pushed any) {
	if set, ok := pushed.(*timer); ok {
		set.index = len(*t)
		*t = append(*t, set)
	}
}

func (t *timers) Pop() any {
	old := *t
	last := old[len(old)-1]
	last.index = -1
	*t = old[:len(old)-1]

	return last
}
