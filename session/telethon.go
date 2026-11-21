package session

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"strings"

	"github.com/i-execute/GTG/vault"
)

var ErrTelethon = errors.New("gtg: invalid Telethon StringSession")

type Telethon struct {
	DCID    int32
	Address string
	Port    uint16
	AuthKey []byte
}

func ParseTelethon(value string) (Telethon, error) {
	var result Telethon
	if len(value) < 2 || value[0] != '1' {
		return result, ErrTelethon
	}
	encoded := strings.TrimSpace(value[1:])
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			return result, ErrTelethon
		}
	}
	if len(raw) != 1+4+2+256 && len(raw) != 1+16+2+256 {
		clear(raw)
		return result, ErrTelethon
	}
	if raw[0] == 0 {
		clear(raw)
		return result, ErrTelethon
	}
	addressLength := len(raw) - 1 - 2 - 256
	address := net.IP(append([]byte(nil), raw[1:1+addressLength]...))
	if address.To4() == nil && address.To16() == nil {
		clear(raw)
		return result, ErrTelethon
	}
	port := binary.BigEndian.Uint16(raw[1+addressLength : 1+addressLength+2])
	if port == 0 {
		clear(raw)
		return result, ErrTelethon
	}
	result.DCID = int32(raw[0])
	result.Address = address.String()
	result.Port = port
	result.AuthKey = append([]byte(nil), raw[1+addressLength+2:]...)
	clear(raw)
	return result, nil
}

func (x Telethon) String() (string, error) {
	if x.DCID < 1 || x.DCID > 255 || x.Port == 0 || len(x.AuthKey) != 256 {
		return "", ErrTelethon
	}
	address := net.ParseIP(x.Address)
	if address == nil {
		return "", ErrTelethon
	}
	if v4 := address.To4(); v4 != nil {
		address = v4
	} else {
		address = address.To16()
	}
	if address == nil {
		return "", ErrTelethon
	}
	raw := make([]byte, 1+len(address)+2+256)
	raw[0] = byte(x.DCID)
	copy(raw[1:], address)
	binary.BigEndian.PutUint16(raw[1+len(address):], x.Port)
	copy(raw[1+len(address)+2:], x.AuthKey)
	value := "1" + base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	return value, nil
}

func (x *Telethon) Destroy() {
	if x == nil {
		return
	}
	clear(x.AuthKey)
	x.AuthKey = nil
	x.DCID = 0
	x.Address = ""
	x.Port = 0
}

func StoreTelethon(target *vault.Vault, name string, value Telethon) error {
	if target == nil || !validName(name) || len(value.AuthKey) != 256 {
		return ErrTelethon
	}
	text, err := value.String()
	if err != nil {
		return err
	}
	data := []byte(text)
	err = target.Put("string-session-"+name, data)
	clear(data)
	return err
}

func LoadTelethon(source *vault.Vault, name string) (Telethon, error) {
	var result Telethon
	if source == nil || !validName(name) {
		return result, ErrTelethon
	}
	secret, err := source.Get("string-session-" + name)
	if err != nil {
		return result, err
	}
	data, err := secret.Bytes()
	secret.Destroy()
	if err != nil {
		return result, err
	}
	result, err = ParseTelethon(string(data))
	clear(data)
	if err != nil {
		result.Destroy()
	}
	return result, err
}

func validName(name string) bool {
	return name != "" && len(name) <= 128 && !strings.ContainsAny(name, "\x00/\\")
}
