package main

import (
	"encoding/hex"
	"encoding/json"
	"os"

	gtg "github.com/i-execute/GTG/core"
)

func main() {
	key := pattern(256, 11)
	plain := pattern(64, 12)
	messageKey, err := gtg.SecretChatMessageKey(key, plain, gtg.SecretChatFromOriginator)
	if err != nil {
		panic(err)
	}
	aesKey, aesIV, err := gtg.DeriveSecretChatAES(key, messageKey[:], gtg.SecretChatToOriginator)
	if err != nil {
		panic(err)
	}
	fingerprint, err := gtg.SecretChatKeyFingerprint(key)
	if err != nil {
		panic(err)
	}
	newNonce := pattern(32, 13)
	serverNonce := pattern(16, 14)
	temporaryKey, temporaryIV, err := gtg.DeriveTemporaryAES(newNonce, serverNonce)
	if err != nil {
		panic(err)
	}
	nonceHash, err := gtg.NewNonceHash(newNonce, key, 1)
	if err != nil {
		panic(err)
	}
	out := map[string]string{
		"aes_iv":            hex.EncodeToString(aesIV[:]),
		"aes_key":           hex.EncodeToString(aesKey[:]),
		"fingerprint":       hex.EncodeToString(fingerprint[:]),
		"message_key":       hex.EncodeToString(messageKey[:]),
		"new_nonce_hash":    hex.EncodeToString(nonceHash[:]),
		"temporary_aes_iv":  hex.EncodeToString(temporaryIV[:]),
		"temporary_aes_key": hex.EncodeToString(temporaryKey[:]),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(out); err != nil {
		panic(err)
	}
}

func pattern(length int, seed byte) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = seed + byte(i*17)
	}
	return out
}
