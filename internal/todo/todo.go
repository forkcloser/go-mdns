// Package todo marks what this module declares and has not built: the
// API is agreed first, and every body that waits for an implementation
// goes through here. The package goes when the last of them does.
package todo

import (
	"errors"
	"fmt"
)

// ErrNotBuilt is what a function that is declared and not built returns,
// when it returns an error.
var ErrNotBuilt = errors.New("not built yet")

// ImplementMe says so on standard output and returns ErrNotBuilt. It
// takes the receiver and the parameters the body will use once built, so
// that they keep the names the API documents them by.
func ImplementMe(...any) error {
	fmt.Println("IMPLEMENT ME") //nolint:forbidigo // the marker of a body not built

	return ErrNotBuilt
}
