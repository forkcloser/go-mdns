//go:build linux || darwin || windows

package mdns_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/forkcloser/go-mdns"
	"github.com/forkcloser/go-mdns/transport"
)

// speaks says whether this environment lets a program say something to
// the group at all: one that does not is not where the host's own
// network can be tried.
func speaks(t *testing.T) {
	t.Helper()

	ctx, stop := context.WithCancel(t.Context())
	defer stop()

	up := make(chan transport.Link, 64)
	ended := make(chan error, 1)

	go func() {
		ended <- transport.System().Watch(ctx, func(event transport.Event) {
			if event.Change == transport.Up {
				up <- event.Link
			}
		})
	}()

	defer func() {
		stop()

		if err := <-ended; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("the watch ended with %v", err)
		}
	}()

	select {
	case link := <-up:
		// A question with nothing in it: no one answers it. Said on
		// every interface there is, since one may refuse where another
		// does not.
		for {
			refused(t, link.Multicast(make([]byte, 12)))

			select {
			case link = <-up:
				continue
			case <-time.After(300 * time.Millisecond):
			}

			break
		}
	case err := <-ended:
		ended <- nil

		unablef(t, "the host's own network cannot be watched here: %v", err)
	case <-time.After(time.Second):
		unablef(t, "the host has no interface that carries multicast")
	}
}

// On the host's own network, with the sockets of the system: a service
// one Peer announces, another finds, at an address of the host's, on an
// interface it has; and loses when it is withdrawn.
func TestOnTheHostsOwnNetwork(t *testing.T) {
	t.Parallel()
	speaks(t)

	unique := make([]byte, 6)
	if _, err := rand.Read(unique); err != nil {
		t.Fatal(err)
	}

	name := "go-mdns-test-" + hex.EncodeToString(unique)
	ctx, stop := context.WithTimeout(t.Context(), 20*time.Second)

	defer stop()

	announcer, err := mdns.Open(ctx, mdns.Config{Hostname: name})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = announcer.Close() }()

	browser, err := mdns.Open(ctx, mdns.Config{})
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = browser.Close() }()

	announced, err := announcer.Announce(ctx, mdns.Service{
		Name: name, Type: "_go-mdns-test._udp", Port: 9, Text: mdns.TXT{{Key: "test", Value: unique}},
	})
	if err != nil {
		t.Fatal(err)
	}

	found, err := browser.Resolve(ctx, name, "_go-mdns-test._udp")
	if err != nil {
		t.Fatalf("not found on the host's own network: %v", err)
	}

	if found.Host != name+".local" || found.Port != 9 || len(found.Addrs) == 0 || len(found.Interfaces) == 0 ||
		len(found.Text) != 1 || !bytes.Equal(found.Text[0].Value, unique) {
		t.Errorf("found %+v", found)
	}

	// Withdrawn, it is gone a second after its goodbye.
	lost := make(chan struct{})

	go func() {
		_ = browser.Browse(
			ctx,
			mdns.Query{Type: "_go-mdns-test._udp", Name: name},
			func(change mdns.Change, _ mdns.Instance) {
				if change == mdns.Lost {
					close(lost)
				}
			},
		)
	}()

	time.Sleep(200 * time.Millisecond)

	if err = announced.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-lost:
	case <-ctx.Done():
		t.Error("not lost after it was withdrawn")
	}
}

// refused leaves the test when the environment is what refused a
// packet to the group.
func refused(t *testing.T, err error) {
	t.Helper()

	if errors.Is(err, os.ErrPermission) {
		unablef(t, "this environment does not let a program send to the group: %v", err)
	}

	// macOS 15 keeps a program it was not told to trust off the local
	// network, and says there is no route: GitHub's runners are such,
	// and nothing in a workflow grants it
	// (https://github.com/actions/runner-images/issues/10924). Skipped
	// under CI too: failing there would fail every run.
	if runtime.GOOS == "darwin" && errors.Is(err, syscall.EHOSTUNREACH) {
		t.Skipf("macOS keeps this program off the local network: %v", err)
	}
}

// unablef leaves a test that cannot be run where it is; and fails it
// under CI, where a leg that skips has run nothing of its system's code.
func unablef(t *testing.T, format string, args ...any) {
	t.Helper()

	if os.Getenv("CI") != "" {
		t.Fatalf(format, args...)
	}

	t.Skipf(format, args...)
}
