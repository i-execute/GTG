//go:build !windows

package vault

import "syscall"

func lockSecretMemory(data []byte) error {
	return syscall.Mlock(data)
}

func unlockSecretMemory(data []byte) error {
	return syscall.Munlock(data)
}
