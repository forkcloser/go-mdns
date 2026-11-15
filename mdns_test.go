package mdns_test

import (
	"testing"

	"github.com/forkcloser/go-mdns"
)

func TestInterfacesAreChosenByName(t *testing.T) {
	t.Parallel()

	wired, air := mdns.Interface{Index: 4, Name: "en0"}, mdns.Interface{Index: 6, Name: "en1"}

	if chosen := mdns.On("en0"); !chosen(wired) || chosen(air) {
		t.Error(`On("en0") is not en0 alone`)
	}

	if chosen := mdns.On(); chosen(wired) || chosen(air) {
		t.Error("On() chooses an interface")
	}
}
