package main

import (
	"crypto/rand"
	"fmt"

	"github.com/i-execute/GTG/mtproto"
)

func main() {
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	box, err := mtproto.New(key)
	if err != nil {
		panic(err)
	}
	defer box.Destroy()
	packet := make([]byte, 24+32, 24+32+1024)
	copy(packet[24:], []byte("packet payload"))
	sealed, err := box.SealInPlace(packet, mtproto.ClientToServer)
	if err != nil {
		panic(err)
	}
	opened, err := box.OpenInPlace(sealed, mtproto.ClientToServer)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(opened))
}
