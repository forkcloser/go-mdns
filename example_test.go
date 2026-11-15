package mdns_test

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/forkcloser/go-mdns"
	"github.com/forkcloser/go-mdns/mdnstest"
)

// A service announced for as long as a program runs.
func ExamplePeer_Announce() {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	peer, err := mdns.Open(ctx, mdns.Config{})
	if err != nil {
		return
	}

	// Close says goodbye for everything announced.
	defer func() { _ = peer.Close() }()

	web, err := peer.Announce(ctx, mdns.Service{
		Name: "Kitchen display",
		Type: "_http._tcp",
		Port: 8080,
		Text: mdns.TXT{{Key: "path", Value: []byte("/")}},
	})
	if err != nil {
		return
	}

	// The name it ended with: another display in another kitchen would
	// have made this one "Kitchen display (2)".
	fmt.Println("announced as", web.Name())

	select {
	case <-ctx.Done():
	case <-web.Done():
		fmt.Println("no longer announced:", web.Err())
	}
}

// A service that is somewhere else, announced for it on one interface:
// what a program beside a service does, when the service cannot speak
// for itself.
func ExamplePeer_Announce_elsewhere() {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	peer, err := mdns.Open(ctx, mdns.Config{})
	if err != nil {
		return
	}

	defer func() { _ = peer.Close() }()

	camera, err := peer.Announce(ctx, mdns.Service{
		Name:       "Garden camera",
		Type:       "_rtsp._tcp",
		Port:       554,
		Host:       "garden-camera",
		Addrs:      []netip.Addr{netip.MustParseAddr("192.0.2.40")},
		Interfaces: mdns.On("en0"),
	})
	if err != nil {
		return
	}

	<-camera.Done()
}

// Every web server on the network, as they come and go.
func ExamplePeer_Browse() {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	peer, err := mdns.Open(ctx, mdns.Config{})
	if err != nil {
		return
	}

	defer func() { _ = peer.Close() }()

	err = peer.Browse(ctx, mdns.Query{Type: "_http._tcp"}, func(change mdns.Change, found mdns.Instance) {
		switch change {
		case mdns.Found, mdns.Changed:
			// Once, however many interfaces it is seen on.
			fmt.Println(found.Name, "at", found.Host, found.Port, found.Addrs, "by", found.Interfaces)
		case mdns.Lost:
			fmt.Println(found.Name, "is gone")
		}
	})

	fmt.Println(err)
}

// One device, by its name, and one host's addresses: each asked for
// until it answers or the patience runs out.
func ExamplePeer_Resolve() {
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()

	peer, err := mdns.Open(ctx, mdns.Config{})
	if err != nil {
		return
	}

	defer func() { _ = peer.Close() }()

	printer, err := peer.Resolve(ctx, "Office printer", "_ipp._tcp")
	if err != nil {
		return
	}

	fmt.Println(printer.Host, printer.Port, printer.Addrs)

	addrs, err := peer.LookupHost(ctx, "nas.local")
	if err != nil {
		return
	}

	fmt.Println(addrs)
}

// What the rest is made of: any record, asked for by name and type.
func ExamplePeer_Ask() {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	peer, err := mdns.Open(ctx, mdns.Config{})
	if err != nil {
		return
	}

	defer func() { _ = peer.Close() }()

	name, err := mdns.ParseName("nas.local")
	if err != nil {
		return
	}

	_ = peer.Ask(ctx, mdns.Question{Name: name, Type: mdns.TypeANY}, func(change mdns.Change, answer mdns.Answer) {
		switch data := answer.Record.Data.(type) {
		case mdns.Addr:
			fmt.Println(change, "address", data.Addr, "by", answer.Interfaces)
		case mdns.NSEC:
			fmt.Println(change, "and no record of any type but", data.Types)
		}
	})
}

// Two peers on a wire of the test's own: what one announces, the other
// finds, with no network and, under testing/synctest, in no time.
func Example_test() {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	var network mdnstest.Network

	wire := mdnstest.Port{Interface: "en0", Wire: "lan"}

	announcer, err := mdns.Open(ctx, mdns.Config{Hostname: "one", Network: network.Host(wire)})
	if err != nil {
		return
	}

	defer func() { _ = announcer.Close() }()

	browser, err := mdns.Open(ctx, mdns.Config{Hostname: "two", Network: network.Host(wire)})
	if err != nil {
		return
	}

	defer func() { _ = browser.Close() }()

	if _, err = announcer.Announce(ctx, mdns.Service{Name: "Lamp", Type: "_hap._tcp", Port: 80}); err != nil {
		return
	}

	lamp, err := browser.Resolve(ctx, "Lamp", "_hap._tcp")
	fmt.Println(lamp.Host, lamp.Port, err)
}
