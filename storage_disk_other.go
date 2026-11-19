//go:build !linux && !windows

package main

import "errors"

func diskSpace(path string) (uint64, uint64, error) {
	return 0, 0, errors.New("disk statistics are supported on Linux and Windows")
}
