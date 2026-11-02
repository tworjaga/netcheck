//go:build !linux && !darwin && !windows

package probe

import "errors"

func setDF(fd int) error { return errors.New("dont-fragment not supported on this OS") }
