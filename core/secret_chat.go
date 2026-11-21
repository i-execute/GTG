package core

import (
	"crypto/sha1"
	"crypto/sha256"
	"errors"
)

var ErrSecretChat = errors.New("gtg: secret chat input rejected")

type SecretChatDirection uint8

const (
	SecretChatFromOriginator SecretChatDirection = iota
	SecretChatToOriginator
)

type SecretChat struct {
	packet      *MTProto
	initialHash [16]byte
}

func NewSecretChat(key []byte) (*SecretChat, error) {
	if len(key) != 256 {
		return nil, ErrAuthKeySize
	}
	packet, err := NewMTProto(key)
	if err != nil {
		return nil, err
	}
	all := sha1.Sum(key)
	chat := &SecretChat{packet: packet}
	copy(chat.initialHash[:], all[:16])
	clear(all[:])
	return chat, nil
}

func SecretChatKeyFingerprint(key []byte) ([8]byte, error) {
	return AuthorizationKeyID(key)
}

func SecretChatMessageKey(key, plaintext []byte, direction SecretChatDirection) ([16]byte, error) {
	if direction > SecretChatToOriginator {
		return [16]byte{}, ErrSecretChat
	}
	return MessageKey(key, plaintext, Direction(direction))
}

func DeriveSecretChatAES(key, messageKey []byte, direction SecretChatDirection) ([32]byte, [32]byte, error) {
	if direction > SecretChatToOriginator {
		return [32]byte{}, [32]byte{}, ErrSecretChat
	}
	return DeriveMessageAES(key, messageKey, Direction(direction))
}

func SecretChatVisualization(initialKey, activeKey []byte) ([36]byte, error) {
	var out [36]byte
	if len(initialKey) != 256 || len(activeKey) != 256 {
		return out, ErrAuthKeySize
	}
	first := sha1.Sum(initialKey)
	second := sha256.Sum256(activeKey)
	copy(out[:16], first[:16])
	copy(out[16:], second[:20])
	clear(first[:])
	clear(second[:])
	return out, nil
}

func (x *SecretChat) Seal(dst, plaintext []byte, direction SecretChatDirection) ([16]byte, []byte, error) {
	if x == nil || x.packet == nil || direction > SecretChatToOriginator {
		return [16]byte{}, nil, ErrSecretChat
	}
	messageKey, ciphertext, err := x.packet.Seal(dst, plaintext, Direction(direction))
	if err != nil {
		return [16]byte{}, nil, ErrSecretChat
	}
	return messageKey, ciphertext, nil
}

func (x *SecretChat) Open(dst, messageKey, ciphertext []byte, direction SecretChatDirection) ([]byte, error) {
	if x == nil || x.packet == nil || direction > SecretChatToOriginator {
		return nil, ErrSecretChat
	}
	plaintext, err := x.packet.Open(dst, messageKey, ciphertext, Direction(direction))
	if err != nil {
		return nil, ErrSecretChat
	}
	return plaintext, nil
}

func (x *SecretChat) SealInPlace(packet []byte, direction SecretChatDirection) ([]byte, error) {
	if x == nil || x.packet == nil || direction > SecretChatToOriginator {
		return nil, ErrSecretChat
	}
	out, err := x.packet.SealInPlace(packet, Direction(direction))
	if err != nil {
		return nil, ErrSecretChat
	}
	return out, nil
}

func (x *SecretChat) OpenInPlace(packet []byte, direction SecretChatDirection) ([]byte, error) {
	if x == nil || x.packet == nil || direction > SecretChatToOriginator {
		return nil, ErrSecretChat
	}
	out, err := x.packet.OpenInPlace(packet, Direction(direction))
	if err != nil {
		return nil, ErrSecretChat
	}
	return out, nil
}

func (x *SecretChat) KeyFingerprint() [8]byte {
	if x == nil || x.packet == nil {
		return [8]byte{}
	}
	return x.packet.AuthorizationKeyID()
}

func (x *SecretChat) InitialVisualizationPrefix() [16]byte {
	if x == nil {
		return [16]byte{}
	}
	return x.initialHash
}

func (x *SecretChat) Destroy() {
	if x == nil {
		return
	}
	if x.packet != nil {
		x.packet.Destroy()
		x.packet = nil
	}
	clear(x.initialHash[:])
}
