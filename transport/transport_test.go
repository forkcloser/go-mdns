package transport_test

import (
	"testing"

	"github.com/forkcloser/go-mdns/transport"
)

func TestTheGroups(t *testing.T) {
	t.Parallel()

	for family, want := range map[transport.Family]string{transport.IPv4: "224.0.0.251", transport.IPv6: "ff02::fb"} {
		if got := transport.Group(family); got.String() != want || !got.IsMulticast() {
			t.Errorf("the group of family %d is %s", family, got)
		}
	}

	for _, neither := range []transport.Family{0, transport.IPv4 | transport.IPv6} {
		if got := transport.Group(neither); got.IsValid() {
			t.Errorf("the group of family %d is %s, and should be none", neither, got)
		}
	}
}
