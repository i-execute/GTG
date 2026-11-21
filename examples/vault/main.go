package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/i-execute/GTG/vault"
)

func main() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	credential, err := vault.NewRawCredential(key)
	if err != nil {
		panic(err)
	}
	store := vault.New()
	defer store.Destroy()
	if err := store.Put("session", []byte("replace with session bytes")); err != nil {
		panic(err)
	}
	path := "session.vault"
	if err := vault.SaveFile(path, store, credential); err != nil {
		panic(err)
	}
	defer os.Remove(path)
	defer os.Remove(path + ".lock")
	loaded, err := vault.LoadFile(path, credential)
	if err != nil {
		panic(err)
	}
	defer loaded.Destroy()
	fmt.Println(loaded.Generation())
}
