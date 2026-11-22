//go:build windows

package vault

func lockSecretMemory(data []byte) error {
	return nil
}

func unlockSecretMemory(data []byte) error {
	return nil
}
