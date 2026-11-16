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
