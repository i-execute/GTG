//go:build windows

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

func withFileLock(path string, exclusive bool, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_ = lock.Close()
			defer os.Remove(path + ".lock")
			return fn()
		}
		if !errors.Is(err, os.ErrExist) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func syncDirectory(path string) error {
	return nil
}
