# mDNS in Go: what exists

A survey of the Go implementations of Multicast DNS ([RFC 6762][6762]) and DNS-Based
Service Discovery ([RFC 6763][6763]), made on 2026-11-14 before writing this one. It
answers three questions: what is there, how is each built, and where does each fall
short.

## How it was made

Each library's source was read at the head of its default branch; nothing was built or
run. Repository figures are GitHub's on that day. Three kinds of statement are kept
apart:

- **read**: seen in the source, and named by file or function;
- **claimed**: said by a README, not checked against the code;
- **inferred**: what the code implies on a system it was not run on, Windows above all.

A handful of the statements the conclusions rest on were read a second time,
independently, and are marked **checked**.

## The short of it

No Go library implements RFC 6762 whole, and none treats the network the way a host with
several interfaces, or a Windows host, needs.

- **Probing and conflict resolution** (§8, §9), which is how a name is known to be free
  and what happens when it is not, exist in one established library, `brutella/dnssd`,
  and there only in part. The `zeroconf` family sends probes and does not read the
  answers.
- **A cache that expires and refreshes** (§5.2, §10) exists in `pion/mdns` and
  `betamos/zeroconf`. `brutella/dnssd` asks once and never again.
- **Every established library uses one socket per address family** and learns which
  interface a packet came in on from a control message. `golang.org/x/net` does not
  implement that on Windows (**checked**), so on Windows each of them guesses, answers on
  every interface, or fails.
- **The two codecs each have a flaw for this use.** `golang.org/x/net/dns/dnsmessage`
  rejects a label that contains a dot (**checked**), which a DNS-SD instance name may;
  `miekg/dns` handles it and is large and allocation-heavy.

## The libraries

Stars and last commit as of 2026-11-14.

| Library | Stars | Last commit | State |
| --- | ---: | --- | --- |
| [hashicorp/mdns] | 1401 | 2026-11 | kept alive; protocol issues open since 2014 |
| [grandcat/zeroconf] | 906 | 2023-01 | unmaintained |
| [pion/mdns] | 284 | 2026-11 | active |
| [oleksandr/bonjour] | 260 | 2021-03 | abandoned; ancestor of zeroconf |
| [brutella/dnssd] | 239 | 2026-02 | one maintainer, slow; fixes unmerged |
| [libp2p/zeroconf] | 28 | 2025-03 | maintenance only |
| [betamos/zeroconf] | 14 | 2025-02 | one author, quiet |
| [joshuafuller/beacon] | 12 | 2026-10 | new (2025-11), active |
| [enbility/zeroconf] | 2 | 2026-04 | active, small audience |
| [cybergarage/go-mdns] | 2 | 2026-10 | active |
| [cB-Sigma/mdns] | 0 | 2026-10 | new (2026-10) |

All are MIT but `cybergarage/go-mdns` and `cB-Sigma/mdns`, which are Apache-2.0. None
uses cgo.

### Against RFC 6762

yes, part, or no, as **read**; *claimed* where only a README says so.

| | Probe §8.1 | Conflict §9 | Goodbye §10.1 | Known answers §7.1 | Cache, re-query §5.2 | Legacy unicast §6.7 |
| --- | --- | --- | --- | --- | --- | --- |
| hashicorp/mdns | no | no | no | no | no | by accident |
| grandcat/zeroconf | sends, never reads | no | yes | PTR only | backoff, no expiry | no |
| libp2p/zeroconf | sends, never reads | no | yes | PTR only | backoff, expiry | no |
| enbility/zeroconf | timing right, never reads | no | yes | PTR only | backoff, expiry, removal told | no |
| betamos/zeroconf | no | no | yes | responder: all types | yes, refresh at 80 to 95% | no |
| oleksandr/bonjour | sends, never reads | no | yes | drops such queries | no | no |
| brutella/dnssd | yes | part: addresses only | PTR only | responder only | no: asks once | part |
| pion/mdns | no | no | not sent, honoured | no | yes, refresh at 80 to 95% | yes |
| beacon | *claimed* | *claimed* | *claimed* later | *claimed* | not read | not read |
| cB-Sigma/mdns | *claimed* | *claimed* | *claimed* | *claimed* | *claimed* | not read |
| cybergarage/go-mdns | yes | not read | yes | not seen | *claimed* | not read |

Nothing here implements duplicate suppression (§7.3, §7.4), response rate limiting (§6)
or the on-link check (§11) in a library meant for general use. `go-fabric`'s package,
below, does, for Matter alone.

### Notes on each

**[hashicorp/mdns].** A responder that answers and never announces, and a one-shot
querier. Its queries leave from an ephemeral port, which makes every one a legacy
unicast query by the RFC's definition (issue 144), and its "multicast" answers are
written to the asker's address, never to the group (`sendResponse` ignores its `unicast`
argument). Used by Consul, Nomad, Serf and Vault.

**[grandcat/zeroconf] and its forks.** The most copied. `probe()` sends two queries and
never looks at a reply; `handleQuery` drops any message with an authority section, which
is what a probe is. Known-answer suppression is for PTR alone. It advertises the
addresses of every interface on every interface (issue 43). [libp2p/zeroconf] adds expiry
of what it found. [enbility/zeroconf] adds a removal channel, interfaces polled at
runtime, and about seventy unit tests behind injectable connections: the best-tested of
the family, with the same protocol gaps (its source carries "TODO: implement a proper
probing & conflict resolution"). [betamos/zeroconf] is mostly a rewrite: a real cache,
known-answer suppression for every type, per-interface addresses, no probing at all
("Probing messages are ignored, for now").

**[brutella/dnssd].** The only established library that probes, renames on conflict, and
was written against Apple's conformance test (a harness is in `cmd/bct`; the log checked
in ends "did not successfully pass"). **Checked**: `probe.go` sends three probes 250 ms
apart and compares addresses. Its weaknesses are on the other side: the browser asks
once and never again (issue 63), sends no known answers, expires its cache only when a
packet arrives, and sleeps under the responder's lock to delay an answer. It is what
[brutella/hap], the Go HomeKit library, runs on.

**[pion/mdns].** Written for WebRTC, where it resolves `.local` host names; DNS-SD is
recent. The best engineered: large unit suites, fuzzing, continuous integration on
Windows, and an end-to-end test against Avahi. It has no probing (a pull request has
been open since 2026-03), sends no goodbye, and sends its questions from ephemeral
ports. **Checked**: `conn.go` treats a packet as a query only when it has more questions
than answers, so a query that carries its known answers is not answered. It builds on
`dnsmessage`, and inherits the dotted-label limit below.

**[joshuafuller/beacon], [cB-Sigma/mdns], [cybergarage/go-mdns].** Three recent
attempts at conformance, each with its own or a light codec. `beacon` ships a runbook
for Apple's conformance test; its transport is one IPv4 socket. `cB-Sigma/mdns` claims
the widest conformance of anything here, has no stars, no Windows run and one month of
history, and was not read beyond its socket code. `cybergarage/go-mdns` opens one
`net.ListenMulticastUDP` socket per interface, so the socket itself says where a packet
came from: the one native library here that does not need a control message.

### Inside other projects

- **[go-fabric]'s `mdns` package** (Matter). The most conformant responder read:
  known-answer suppression with the truncation wait, unicast and legacy unicast answers,
  the one-second rate limit, duplicate-question suppression, the on-link check, goodbyes.
  It does not probe, by design, and says it "does not aim to be a general-purpose mDNS
  stack": its service model and announcement schedule are Matter's. **Checked**: its
  sockets treat `SetControlMessage` failing as fatal, so on Windows its querier cannot
  open; and its responder drops every packet whose interface is unknown, so tolerating
  the failure would not be enough.
- **[go2rtc]'s `pkg/mdns`** (14.6k stars). IPv4 only, no probing, no cache. Worth
  reading for one thing (**checked**): it opens one sending socket per interface
  address, bound to that address on port 5353, and needs no control message. It targets
  Windows on purpose.
- **Others that carry their own**: `go-micro` (a copy of the hashicorp line), `nextdns`
  and `portmaster` (queriers only), `pretender` (a spoofer, with a separate IPv6 path
  for Windows), `external-mdns`.
- **Ports**: `hilli/gothread` ports OpenThread's `mdns.cpp` to Go, with 83 KB of tests;
  `soypat/lneto` and `shabunin/tiny-matter-go` are for TinyGo.

### Bindings to a system daemon

Avahi over D-Bus ([holoplot/go-avahi], pure Go) or through `libavahi-client`
([OpenPrinting/go-avahi], cgo); Apple's `dns_sd.h` through cgo (several, small and old).
No Go library was found for Windows' own `DnsServiceBrowse` and `DnsServiceRegister`.

## What they are built on

### The codec

| | `miekg/dns` | `x/net/dns/dnsmessage` |
| --- | --- | --- |
| Top bit of the class (QU, cache-flush) | kept; the caller masks it | kept; the caller masks it |
| A label with a dot in it | yes, escaped | **no**: packing splits on it, unpacking refuses the packet |
| NSEC | yes | no: an opaque blob |
| Name compression of an SRV target | never (RFC 6762 §18.14 asks for it) | never |
| Allocation | one object per record | can be none, with `Parser` and `Builder` |
| Weight | large; pulls `x/net`, `x/sys`, `x/sync` | none |

**Checked**: `dnsmessage` returns `errInvalidName` for a label containing a dot
(`message.go`, citing golang/go#56246). One such record makes `Message.Unpack` fail for
the whole packet, and a DNS-SD instance name such as `Living Room 2.4GHz` is one.

### The sockets

What `golang.org/x/net/ipv4` and `ipv6` do, per system (**checked** for Windows in
x/net v0.62.0: `control_windows.go` returns `errNotImplemented`, and the build tag of
`payload_nocmsg.go` puts Windows among the systems with no control message):

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Join a group on an interface | yes | yes | yes |
| Choose the interface a socket sends on | yes | yes | yes |
| Be told the interface a packet came in on | yes | yes | **no** |
| Choose the interface for one packet | yes | yes | **no**, silently ignored |
| Read or write in batches | yes | one at a time | **no** |

So there are two ways to know where a packet came from, and they do not work in the same
places:

- **One socket per family, and a control message.** Works on Linux and macOS through
  `x/net`. On Windows it needs `IP_PKTINFO` and `WSARecvMsg` by hand.
- **One socket per interface.** The socket is the answer. On Windows, a socket bound to
  the interface's address receives the multicast joined on it (*inferred*, and what
  `go2rtc` does). On Linux such a socket receives no multicast: it must bind the
  wildcard and be tied to the interface with `SO_BINDTODEVICE`, or filter. On macOS,
  `IP_BOUND_IF`.

Everything established takes the first way and stops at `x/net`. On Windows they then
match the source address against interface subnets (`brutella/dnssd`), answer on every
interface (`grandcat`, `pion`, `betamos`), or fail (`go-fabric`).

IPv6 adds its own: the group is link-scoped, so every join and send names an interface,
and a reply to a link-local source needs its zone.

## What there is to test against

- **Apple's Bonjour Conformance Test** is the only real suite. It is closed, runs on a
  Mac against a device on the network, and tests probing, injected conflicts, interfaces
  going and coming, and more. `brutella/dnssd` and `beacon` carry harnesses for it.
- **No open equivalent was found.** In practice: interoperation with Avahi and Apple's
  mDNSResponder, as `pion/mdns` and `cB-Sigma/mdns` automate.
- **The yardsticks**: Apple's mDNSResponder, by the RFC's authors; Avahi, the Linux
  default; `python-zeroconf`, which Home Assistant runs and is the most tested against
  consumer devices; Rust's `mdns-sd`; OpenThread's mDNS for Matter and Thread.

## What follows for this one

1. **The gap is real.** Nothing combines a conformant responder (probing, conflicts,
   known answers, rate limits) with a browser that keeps a cache, in a general-purpose
   library. The nearest are `brutella/dnssd` for the first half and `pion/mdns` for the
   second.
2. **Know the interface, on every system.** This is where every existing library is
   weakest, and Windows is where it shows. The design has to start from how a packet's
   interface is known on each of Linux, macOS and Windows, with a run on each.
3. **A codec of its own.** Small, without allocation on the read path, with dotted
   labels, NSEC, and compression of SRV targets: neither existing codec has all four.
4. **A transport that can be replaced.** `enbility/zeroconf` and `go-fabric` show what
   it buys: the protocol tested without a network. `tiny-matter-go` goes furthest, with
   a transport that is one function.
5. **Conformance as a test, from the first day.** A harness for Apple's test, and
   interoperation with Avahi in continuous integration, as `pion/mdns` has.
6. **Read before writing**: `brutella/dnssd`'s probing; `betamos/zeroconf`'s and
   `pion/mdns`'s caches; `go-fabric`'s answering and rate limits; `go2rtc`'s sockets;
   `gothread`, as a port of a certified implementation.

[6762]: https://www.rfc-editor.org/rfc/rfc6762
[6763]: https://www.rfc-editor.org/rfc/rfc6763
[hashicorp/mdns]: https://github.com/hashicorp/mdns
[grandcat/zeroconf]: https://github.com/grandcat/zeroconf
[libp2p/zeroconf]: https://github.com/libp2p/zeroconf
[enbility/zeroconf]: https://github.com/enbility/zeroconf
[betamos/zeroconf]: https://github.com/betamos/zeroconf
[oleksandr/bonjour]: https://github.com/oleksandr/bonjour
[brutella/dnssd]: https://github.com/brutella/dnssd
[brutella/hap]: https://github.com/brutella/hap
[pion/mdns]: https://github.com/pion/mdns
[joshuafuller/beacon]: https://github.com/joshuafuller/beacon
[cB-Sigma/mdns]: https://github.com/cB-Sigma/mdns
[cybergarage/go-mdns]: https://github.com/cybergarage/go-mdns
[go-fabric]: https://github.com/SukramJ/go-fabric
[go2rtc]: https://github.com/AlexxIT/go2rtc
[holoplot/go-avahi]: https://github.com/holoplot/go-avahi
[OpenPrinting/go-avahi]: https://github.com/OpenPrinting/go-avahi
