# go-mdns

Multicast DNS ([RFC 6762](https://www.rfc-editor.org/rfc/rfc6762)) and DNS-Based Service
Discovery ([RFC 6763](https://www.rfc-editor.org/rfc/rfc6763)) in Go.
[What exists](docs/landscape.md) says what it was designed against, and
[the design](docs/design.md) why its API is shaped as it is and what it promises of the
two RFCs, section by section.

It implements the protocol whole: a responder that asks for its names before it uses
them and defends them after, a browser that keeps what it hears for as long as it was
told to, over IPv4 and IPv6, on every interface of the host and knowing which, on Linux,
macOS and Windows alike, with no dependency but Go's standard library.

```go
peer, err := mdns.Open(ctx, mdns.Config{})
if err != nil {
	return err
}

defer peer.Close()

// Offer a service.
web, err := peer.Announce(ctx, mdns.Service{Name: "Kitchen display", Type: "_http._tcp", Port: 8080})

// Find those of others.
err = peer.Browse(ctx, mdns.Query{Type: "_http._tcp"}, func(change mdns.Change, found mdns.Instance) {
	fmt.Println(change, found.Name, found.Host, found.Port, found.Addrs, found.Interfaces)
})
```

Tests of code that uses it need no network: [`mdnstest`](mdnstest/mdnstest.go) is hosts
and wires in the test's process, on which Peers find each other as they would on a real
one, and with `testing/synctest` an hour of the protocol takes no time.

## What is proven, and where

Nearly all of the tests run on `mdnstest`, on every platform. Two go through the
system's own sockets, with two programs on one host hearing each other and a service
announced and found; where they run decides what is proven of each system's transport:

| System | The two tests on real sockets |
|--------|-------------------------------|
| Linux | Run in continuous integration, on x86-64 and arm64. |
| Windows | Run in continuous integration, on x86-64 and arm64. |
| macOS | Not run in continuous integration: GitHub's macOS runners keep a program off the local network ([runner-images#10924](https://github.com/actions/runner-images/issues/10924)), and the tests skip there. Run by hand in a terminal on a Mac, where they pass. |

So a change to the macOS transport is not held by continuous integration: run
`just test` on a Mac before trusting it. What the library does not do yet, and has not
been measured against, is [in the tracker](docs/design.md#still-to-settle): among it,
no run of a conformance suite.

## The command

A service that cannot speak the protocol itself is announced by a program run beside it:

```bash
go install github.com/forkcloser/go-mdns/cmd/mdns@latest
```

```bash
mdns announce --type _http._tcp --port 8080 --name "Kitchen display" --txt path=/
```

or, for everything a host offers at once, from a JSON document
([the design](docs/design.md#the-command) has its fields):

```bash
mdns announce services.json
```

It announces until it is told to stop, and says what happens as JSON on standard output.
`mdns browse`, `mdns resolve` and `mdns lookup` look
at a network by hand.
