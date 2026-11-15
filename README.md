# go-mdns

Multicast DNS ([RFC 6762](https://www.rfc-editor.org/rfc/rfc6762)) and DNS-Based Service
Discovery ([RFC 6763](https://www.rfc-editor.org/rfc/rfc6763)) in Go. This is the
repository's baseline; [a survey of what exists](docs/landscape.md) comes first, and the
code after it.

The aim is a library that implements the protocol whole, a responder that probes and a
browser that keeps a cache, and that knows which interface a packet came in on, on Linux,
macOS and Windows alike.
