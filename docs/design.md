# The design

This is the design of go-mdns's API, agreed before it is built. The API itself is in the
packages, as Go; this document holds what the code cannot say: what the API holds itself
to, the decisions in it and why, what it promises of the protocol, and what is left out.
[What exists](landscape.md) says what it was designed against.

## What it is for

A host on a network has things to offer its neighbours and things to find among them,
with no server to ask. Multicast DNS ([RFC 6762][6762]) is how names are asked for and
answered on a link; DNS-Based Service Discovery ([RFC 6763][6763]) is what those names
say of services. go-mdns is both, whole, for a Go program: to announce and to find, over
IPv4 and IPv6, on every interface a host has.

## Where it is

| Package | What it is |
| --- | --- |
| [`mdns`](../mdns.go) | a host's part in the protocol, a `Peer`: [services announced](../service.go), [services found](../browse.go), [records](../record.go), [names](../name.go) |
| [`transport`](../transport/transport.go) | where packets go and come from: a host's links, the system's or another's |
| [`mdnstest`](../mdnstest/mdnstest.go) | hosts and wires in a test's process |

Examples, compiled with the code: [announcing, announcing for a service that is somewhere
else, browsing, resolving, asking, and two peers on a wire](../example_test.go).

Built: everything but the host's own network. Names and the rules a service is held to;
the reading and writing of messages ([`internal/wire`](../internal/wire/wire.go)); records
asked for and answered for ([`internal/engine`](../internal/engine/engine.go)); services
announced and found on them ([`announce.go`](../announce.go), [`browser.go`](../browser.go),
[`host.go`](../host.go)); and the network of tests. `transport.System` and the command go
through [`internal/todo`](../internal/todo/todo.go), which prints `IMPLEMENT ME` and
returns an error: until they are built a Peer is opened on a `Network` it is given.

## What the API holds itself to

1. **One Peer, for asking and for answering.** The protocol means a host's questions and
   its answers to share port 5353 and one memory of what was heard: a question from any
   other port is answered as to a stranger, and what one browser learns another should
   not ask again. So there is one thing to open, and everything else is asked of it.
2. **Kept apart by link, told together.** Nothing that reaches a device on one link
   reaches it on another, so a Peer asks, answers and remembers for each interface on its
   own, as RFC 6762 §14 has it. What it tells a program is merged: one instance, with
   the interfaces it is seen on. What is announced goes to every interface with that
   interface's own addresses, or to the interfaces chosen for it.
3. **The spec, whole, and by default.** Probing, defending a name, known answers, the
   rate limits, goodbyes, a cache that runs out and is refreshed: none is an option. What
   RFC 6762 says a host must or should do, a Peer does without being asked.
4. **Three levels, each made of the next.** Services, hosts, records. The first two are
   what most programs want and are written in terms of the third, which is exported so
   that nothing is out of reach and nothing is magic.
5. **State is a value, change is a call.** What is found is handed over whole, as it
   stands; a change says what it is and carries the whole again. A watcher is first told
   everything already known, so there is no reading first and watching after.
6. **Open, or not at all; the zero value works.** `Open` returns a Peer that works, or an
   error. The zero `Config` is every interface, both families, the host's own name. A
   host with no network is not an error: links are taken up as they come.
7. **Names are not strings.** A domain name is its labels. An instance called
   "Living Room 2.4GHz" is one label with a dot in it, and no escaping stands between a
   program and its own names.
8. **The network is a parameter.** A Peer speaks over a `transport.Network`: the
   system's, a network stack in user space, or a test's wires. The protocol is tested on
   the last, in no time, and the system's is tested for what only it can get wrong.

## The decisions, and why

- **A `Peer`, not a responder and a browser.** Every Go library but one splits them, and
  pays for it: queries from an ephemeral port, two caches, two sets of sockets on one
  port. A Peer that only looks announces nothing, its host name included.
- **A handler called in order; not a channel, and not an iterator.** `Browse`, `Ask` and
  `ServiceTypes` take a function, call it on the caller's own goroutine, and return when
  their context ends. A channel has to be given a size, and then either drops a `Lost`
  when a reader is slow or holds the protocol back for it; it cannot say why it closed.
  An iterator (`for change, instance := range`) reads well and has nowhere to put the
  error it ends with, nor a way to say that the loop blocks for as long as the program
  runs. A function has neither problem, and either of the other two is five lines on top
  of it. A handler that is slow holds back its own `Browse` and nothing else: what it
  missed meanwhile is told as where things stand, not as every step.
- **An instance is found when it can be used.** `Browse` tells of an instance once its
  SRV and TXT records are known, and again when its addresses are. `Query.Unresolved`
  is for a list of names, and asks nothing more.
- **Found once, with its interfaces.** A printer on the wire and over the air is one
  `Instance`, whose `Interfaces` says both and whose `Addrs` holds every address it has
  by either. It is changed when an interface is added or goes, and lost when none is
  left. What makes two sightings one instance is the name, the type, and the host and
  port they give: RFC 6762 §14 lets two links each have a host of the same name, and
  those stay two. The same holds for a record (`Answer`) and a type (`ServiceType`).
- **Where to ask and where to announce is a rule, at three levels.** `Config.Interfaces`
  is where the Peer is at all; `Service.Interfaces` and `Records.Interfaces` choose among
  those for one announcement; `Query.Interfaces` and `Question.Interfaces` for one
  question. Each is a function, `On("en0")` being the common one, and nil is all: an
  interface that comes up later is asked the same question as those that were there.
- **A name taken is renamed, and the program is asked.** `Rename` is given the name that
  was refused and answers the next. Nil is the numbering RFC 6762 suggests. `Never`
  gives up, for a name that has to be exactly what it is. It is asked at any time, since
  a conflict can come later, which also makes it the notice of a renaming.
- **`Announce` returns when it is announced.** That is after probing, about a second:
  the caller then knows the name it has. On a link that comes up later the same is done
  again, without it.
- **A text record keeps its order, its bytes, and the difference between no value and
  an empty one.** RFC 6763 gives all three a meaning; a map of strings has none of them.
- **Only the text of a service changes.** RFC 6762 has a way to tell of a changed
  record, and a service's text is what changes in practice. A new port or host is a new
  announcement.
- **A service somewhere else is `Host` and `Addrs`, together.** A program that runs
  beside a service and announces it, for a device or a container that cannot speak for
  itself, gives the name of the host the service is on and the addresses it is at.
  They need be none of this host's: RFC 6762 §14 holds a host's own addresses to the
  interface they are on, "except in the case of proxying". An address needs a name to
  be the address of, which is why there is no giving one without the other.
- **What cannot be reached can be doubted.** Only the program knows that a connection
  to what was found failed. `Reconfirm` says so, and the Peer asks again and forgets
  what no one confirms, as RFC 6762 §10.4 has a cache do.
- **Which addresses are announced is a function.** All of an interface's own, by
  default; a host that would keep a temporary IPv6 address to itself says so.
- **No clock in the API.** `testing/synctest` makes the protocol's seconds and hours
  pass at once in a test, with the real clock in the code.
- **Logging is `log/slog`'s default.** The host says where it goes, once.
- **A codec of its own, and not exported.** Neither existing codec carries a dotted
  label, NSEC and a compressed SRV target without allocating for every record. It stays
  inside: what a program needs of it is `Name`, `Record` and the data types.

## The command

The library has two kinds of user. A program that looks for services links it and calls
`Browse`. A service that wants to be found often cannot: it is written in something else,
or is a device, or should not carry the protocol. For those there is a command, run
beside the service, which is `Announce` and nothing more:

```
mdns announce services.json
mdns announce -              # the same document, on standard input
```

What to announce is a JSON document, since what runs a program beside a service is
itself a program, and since one process then announces everything a host or a pod
offers through one Peer:

```json
{
  "hostname": "kitchen",
  "services": [
    {
      "name": "Kitchen display",
      "type": "_http._tcp",
      "port": 8080,
      "subtypes": ["_printer"],
      "text": ["path=/", "secure"],
      "interfaces": ["en0"],
      "ttl": "2m",
      "rename": false
    },
    {
      "name": "Garden camera",
      "type": "_rtsp._tcp",
      "port": 554,
      "host": "garden-camera",
      "addresses": ["192.0.2.40"]
    }
  ]
}
```

- **A service is a `Service`, field for field**: `name`, `type`, `port`, `subtypes`,
  `text`, `priority`, `weight`, `host` and `addresses`, `interfaces`, `ttl`. Only `type`
  and `port` are required. `rename` is `true` when left out, the numbering; `false` is
  `Never`. `hostname`, beside `services`, is `Config.Hostname`.
- **`text` is a list, in the order it is sent.** Each entry is a string as it goes on
  the wire, `"key=value"`, or `"key"` for a key with no value, which a JSON object could
  neither order nor tell from an empty one. A value that is not text is
  `{"key": "id", "base64": "3q2+7w=="}`.
- **A field it does not know is an error**, with where it is: a misspelt `"prot"` that
  announces port zero is worse than a refusal.
- **What it says is JSON too**, one object on a line on standard output for each thing
  that happens: a service announced, with the name it ended up with and the name asked
  for; one renamed later; one lost to another host. What goes wrong goes to standard
  error.
- **It announces until it is told to stop**, and says goodbye for everything on the way
  out. When a name is taken and `rename` is `false`, it withdraws everything and leaves
  with an error: a host half announced is not what was asked for.
- **Told to read again (SIGHUP), it applies the difference**: a service that is new is
  announced, one that is gone is withdrawn, one whose text alone changed is updated, and
  the others are left alone.

For one service typed by hand, the same fields are flags, and no document is needed:
`mdns announce --type _http._tcp --port 8080 --name "Kitchen display" --txt path=/`.

`mdns browse`, `mdns resolve` and `mdns lookup` are the same three calls of the library,
for looking at a network by hand; they print JSON as well. The command is declared here
and built with the rest. It adds nothing to the library's API, which is what holds the
API to being enough for it.

## What it promises of the protocol

What a Peer does, by the section that asks for it. None of it is built yet; each line is
what the implementation is held to, and what its tests are for. Every line was checked
against the text of the two RFCs, and four things the text asks for were missing from the
API and were added for it: `Reconfirm` (§10.4), a choice of where to ask (§14), a link's
MTU (§17), and the IP TTL of what a link sends (§11).

| RFC 6762 | A Peer |
| --- | --- |
| §5.1 one-shot queries | never sends one: it asks from port 5353 |
| §5.2 continuous querying | waits 20 to 120 ms before a first question, a second before the next, and doubles from there up to an hour, for as long as something is asked; once a name's one holder has answered, asks only to keep the answer |
| §5.2 cache maintenance | asks again at 80, 85, 90 and 95% of a record's life, each up to 2% late, only for what is still looked for, and forgets the record at the end |
| §5.4 unicast responses | asks for one only for what it has to ask as it comes to a link; answers by one when asked, unless the record was not said to all for a quarter of its life |
| §5.5 direct unicast | answers a question sent to it alone as one asking for unicast, when it comes from the link |
| §6 responding | says only records that are its own; answers within 10 ms for what is its alone, after 20 to 120 ms for what others may also answer, after 400 to 500 ms a question cut short; says no record to all twice in a second, a probe's answer aside |
| §6 what is heard | takes no response from another port than 5353, and none sent to it alone but for a question it asked that way in the last two seconds |
| §6.1 negative responses | says with NSEC which types its names have not, in the restricted form, without the NSEC bit |
| §6.2 addresses | says all of an interface's own addresses on it and none of another's; the other family's with them, or that there is none |
| §6.3 to §6.5 | answers every question of a message, in one message where it can, and with all it has for ANY |
| §6.6 cooperating | takes the same record from another host as no conflict, and says its own again when the other's is to be forgotten in under half the time |
| §6.7 legacy unicast | answers a question from another port to that port, the ID and the question repeated, no TTL over ten seconds, no record marked as its alone, no SRV target compressed |
| §7.1 known answers | says what it knows when it asks, if it has over half its life left; does not say what the asker knows with half of it left; learns nothing from what an asker says it knows |
| §7.2 many known answers | marks a question cut short and sends the rest after it; waits for the rest of one |
| §7.3, §7.4 duplicates | does not ask what was just asked, nor answer what was just answered |
| §8.1 probing | waits up to 250 ms, then asks three times, 250 ms apart, for any record of a name that is to be its alone, asking for unicast; after fifteen conflicts in ten seconds, waits five before each try |
| §8.2 simultaneous probes | compares its records with a rival's as the RFC orders them; holds, or yields and asks again a second later |
| §8.3 announcing | says its records twice, a second apart, and not again without cause |
| §8.4 updating | says a changed record again, without asking for its name again; says goodbye to what a shared record was, first |
| §9 conflicts | goes back to asking when another host says a record of a name that is its alone, at any time; takes another name by `Rename` when it loses; logs it when a minute finds none |
| §10 lifetimes | 120 seconds for what names a host, 75 minutes for the rest |
| §10.1 goodbyes | says so, with a TTL of zero, for everything withdrawn; keeps a second what it is told goodbye for |
| §10.2 cache flush | marks what is its alone, and says the whole set; forgets, a second later, what it heard of a set more than a second before another said it whole |
| §10.3 links | forgets what it heard on a link that goes down |
| §10.4 failures | `Reconfirm`: asks twice, and forgets what no one confirms in ten seconds |
| §10.5 failures seen | forgets what two questions of others should have brought and did not, in ten seconds, without asking itself |
| §11 source address | sends with an IP TTL of 255; takes nothing sent to it alone from off the link |
| §14 interfaces | defends its name on every interface, and takes another on all of them when it loses on one; keeps apart two hosts of one name on two links |
| §15 sharing the port | shares port 5353 with the system's responder |
| §16 names | UTF-8, compared as DNS does: ASCII letters without their case, every other byte as it is |
| §17 messages | to the link's MTU, headers counted; one record alone up to 9000 bytes, headers counted |
| §18 format | an ID of zero, and none looked at; answers marked authoritative; names compressed, in the data of an SRV record too, and read so |

| RFC 6763 | A Peer |
| --- | --- |
| §4.1.1 instance names | any text of up to 63 bytes, a dot included, an ASCII control character aside |
| §4.3 names written | dots and backslashes of a label escaped, where a name is written as one string |
| §5 resolving | an instance's SRV and TXT records, and one `Instance` for each host a name has |
| §6.1 to §6.5 text records | order, bytes, and no value apart from an empty one; keys of printable ASCII, without their case, the first of two the same when read and refused when written; always a record, with one empty string if nothing else |
| §7 service names | held to RFC 6335 and to `_tcp` or `_udp` when announced; taken as they come when found |
| §7.1 subtypes | announced and browsed, as any label of up to 63 bytes |
| §9 service types | every type announced is said under `_services._dns-sd._udp`; enumerated by `ServiceTypes` |
| §12 additional records | sends an instance's SRV, TXT and addresses with its PTR, and a host's addresses with an SRV; asks for them when another does not |

## How the network is known

`transport.System` has to answer, on each system, which interface a packet came in on.
[What exists](landscape.md) found that this is where every Go library is weakest. The
plan, to be proven by a run on each system and not before:

- **Linux and macOS**: one socket for each family, on port 5353, joined to the group on
  every interface, with the packet's interface read from its control message.
- **Windows**: `golang.org/x/net` gives no control message there. Either one socket for
  each interface, bound to its address, or the packet information read through the
  system's own calls. Which, is for a run on Windows to say.

A `Link` hides the difference. That is what it is for.

## Left out, on purpose

- **Unicast DNS-SD.** Browsing a domain other than `local` through a DNS server is
  another protocol with the same records.
- **Domain enumeration** (RFC 6763 §11). There is one domain here.
- **Relaying between links.** A reflector is a program written with this library, not
  part of it.
- **Sleep proxies, and long-lived queries.**
- **The system's own responder**, as a way in. This is an implementation, not a binding.
- **Several text records for one instance** (RFC 6763 §6.8). One service type uses
  them. `Publish` can say them and `Ask` can read them; `Service` and `Instance` have
  one.

## To settle when it is built

1. **Windows.** Which of the two ways, and whether a socket there can share port 5353
   with the system's own responder and still be answered by unicast.
2. **Unicast answers beside a system responder**, on any system. Two programs on one
   port: the system hands a packet sent to the host alone to the first that bound it.
   RFC 6762 §15.1 has the second detect that and stop asking for unicast answers; how
   `transport.System` tells, and how it says so to the Peer, is for the build.
3. **Conformance.** Apple's Bonjour Conformance Test is the one real suite, runs on a
   Mac against a device on the network, and is closed. A harness for it, and
   interoperation with Avahi and Apple's responder in continuous integration, are what
   "the spec, whole" will be measured by.
4. **IPv6 addresses worth announcing.** Which of an interface's the default leaves out:
   a temporary address cannot be told from another on every system.

[6762]: https://www.rfc-editor.org/rfc/rfc6762
[6763]: https://www.rfc-editor.org/rfc/rfc6763
