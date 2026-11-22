package vault

import (
	"os"
	"path/filepath"
)

func SaveFile(path string, vault *Vault, credential Credential) error {
	if path == "" || vault == nil {
		return ErrCredential
	}
	return withFileLock(path, true, func() error {
		encoded, err := vault.Marshal(credential)
		if err != nil {
			return err
		}
		defer clear(encoded)
		return writeAtomic(path, encoded)
	})
}

func LoadFile(path string, credential Credential) (*Vault, error) {
	if path == "" {
		return nil, ErrCredential
	}
	var vault *Vault
	err := withFileLock(path, false, func() error {
		encoded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		defer clear(encoded)
		vault, err = Open(encoded, credential)
		return err
	})
	if err != nil {
		return nil, err
	}
	return vault, nil
}

func RotateFile(path string, oldCredential, newCredential Credential) error {
	if path == "" {
		return ErrCredential
	}
	return withFileLock(path, true, func() error {
		encoded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		defer clear(encoded)
		vault, err := Open(encoded, oldCredential)
		if err != nil {
			return err
		}
		defer vault.Destroy()
		replacement, err := vault.Marshal(newCredential)
		if err != nil {
			return err
		}
		defer clear(replacement)
		return writeAtomic(path, replacement)
	})
}

func writeAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func ExportPortable(vault *Vault, credential Credential) (string, error) {
	encoded, err := vault.Marshal(credential)
	if err != nil {
		return "", err
	}
	defer clear(encoded)
	return EncodePortable(encoded), nil
}

func ImportPortable(value string, credential Credential) (*Vault, error) {
	encoded, err := DecodePortable(value)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return Open(encoded, credential)
}
