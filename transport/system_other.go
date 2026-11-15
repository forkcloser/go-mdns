//go:build !linux && !darwin && !windows

package transport

import (
	"context"
	"errors"
	"fmt"
)

// System is the host's own network. It is not built for this system:
// its Watch returns errors.ErrUnsupported.
func System() Network { return system{} }

type system struct{}

func (system) Watch(context.Context, func(Event)) error {
	return fmt.Errorf("the host's own network: %w", errors.ErrUnsupported)
}
