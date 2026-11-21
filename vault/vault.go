package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"sort"
	"sync"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

var ErrAuthentication = errors.New("gtg vault: authentication failed")
var ErrCredential = errors.New("gtg vault: invalid credential")
var ErrSecret = errors.New("gtg vault: invalid secret")
var ErrDestroyed = errors.New("gtg vault: destroyed")

const (
	formatMagic    = "GTVL"
	formatVersion  = 1
	payloadVersion = 1
	maxHeader      = 1024
	maxPayload     = 64 << 20
	maxSecret      = 65535 - 1026
)

type KeyMode uint8

const (
	RawKey KeyMode = iota + 1
	MachineKey
	Passphrase
)

type KDF uint8

const (
	Argon2id KDF = iota + 1
	PBKDF2SHA256
)

type KDFParameters struct {
	Algorithm  KDF
	Time       uint32
	MemoryKiB  uint32
	Threads    uint8
	Iterations uint32
}

type Credential struct {
	Mode       KeyMode
	Key        []byte
	Passphrase []byte
	KDF        KDFParameters
}

type Secret struct {
	mu        sync.RWMutex
	data      []byte
	locked    bool
	destroyed bool
}

type Vault struct {
	mu         sync.RWMutex
	entries    map[string]*Secret
	generation uint64
	destroyed  bool
}

func DefaultArgon2id() KDFParameters {
	return KDFParameters{Algorithm: Argon2id, Time: 3, MemoryKiB: 65536, Threads: 1}
}

func DefaultPBKDF2() KDFParameters {
	return KDFParameters{Algorithm: PBKDF2SHA256, Iterations: 600000}
}

func NewRawCredential(key []byte) (Credential, error) {
	if len(key) != 32 {
		return Credential{}, ErrCredential
	}
	return Credential{Mode: RawKey, Key: key}, nil
}

func NewMachineCredential(key []byte) (Credential, error) {
	if len(key) != 32 {
		return Credential{}, ErrCredential
	}
	return Credential{Mode: MachineKey, Key: key}, nil
}

func NewPassphraseCredential(passphrase []byte, parameters KDFParameters) (Credential, error) {
	if len(passphrase) == 0 || !validKDF(parameters) {
		return Credential{}, ErrCredential
	}
	return Credential{Mode: Passphrase, Passphrase: passphrase, KDF: parameters}, nil
}

func New() *Vault {
	return &Vault{entries: make(map[string]*Secret)}
}

func NewSecret(data []byte) (*Secret, error) {
	if len(data) == 0 || len(data) > maxSecret {
		return nil, ErrSecret
	}
	out := &Secret{data: append([]byte(nil), data...)}
	return out, nil
}

func (x *Secret) Bytes() ([]byte, error) {
	if x == nil {
		return nil, ErrDestroyed
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.destroyed {
		return nil, ErrDestroyed
	}
	return append([]byte(nil), x.data...), nil
}

func (x *Secret) LockMemory() error {
	if x == nil {
		return ErrDestroyed
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.destroyed {
		return ErrDestroyed
	}
	if x.locked {
		return nil
	}
	if err := syscall.Mlock(x.data); err != nil {
		return err
	}
	x.locked = true
	runtime.KeepAlive(x.data)
	return nil
}

func (x *Secret) Destroy() {
	if x == nil {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.destroyed {
		return
	}
	if x.locked {
		_ = syscall.Munlock(x.data)
		x.locked = false
	}
	clear(x.data)
	x.data = nil
	x.destroyed = true
	runtime.KeepAlive(x)
}

func (x *Vault) Put(name string, data []byte) error {
	if !validName(name) {
		return ErrSecret
	}
	secret, err := NewSecret(data)
	if err != nil {
		return err
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.destroyed {
		secret.Destroy()
		return ErrDestroyed
	}
	previous := x.entries[name]
	x.entries[name] = secret
	x.generation++
	if previous != nil {
		previous.Destroy()
	}
	return nil
}

func (x *Vault) Get(name string) (*Secret, error) {
	if x == nil {
		return nil, ErrDestroyed
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.destroyed {
		return nil, ErrDestroyed
	}
	secret := x.entries[name]
	if secret == nil {
		return nil, ErrSecret
	}
	data, err := secret.Bytes()
	if err != nil {
		return nil, err
	}
	out, err := NewSecret(data)
	clear(data)
	return out, err
}

func (x *Vault) Delete(name string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x == nil || x.destroyed {
		return ErrDestroyed
	}
	secret := x.entries[name]
	if secret == nil {
		return ErrSecret
	}
	delete(x.entries, name)
	x.generation++
	secret.Destroy()
	return nil
}

func (x *Vault) Generation() uint64 {
	if x == nil {
		return 0
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.generation
}

func (x *Vault) Destroy() {
	if x == nil {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.destroyed {
		return
	}
	for key, secret := range x.entries {
		secret.Destroy()
		delete(x.entries, key)
	}
	x.destroyed = true
}

func (x *Vault) Marshal(credential Credential) ([]byte, error) {
	payload, generation, err := x.payload()
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	header, key, err := newHeader(credential, generation, rand.Reader)
	if err != nil {
		return nil, err
	}
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, ErrCredential
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCredential
	}
	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	prefix := make([]byte, 8+len(header)+len(nonce))
	copy(prefix[:4], formatMagic)
	binary.LittleEndian.PutUint16(prefix[4:6], formatVersion)
	binary.LittleEndian.PutUint16(prefix[6:8], uint16(len(header)))
	copy(prefix[8:], header)
	copy(prefix[8+len(header):], nonce[:])
	out := aead.Seal(prefix, nonce[:], payload, prefix[:8+len(header)])
	clear(header)
	clear(nonce[:])
	return out, nil
}

func Open(encoded []byte, credential Credential) (*Vault, error) {
	header, nonce, ciphertext, aad, err := parseEnvelope(encoded)
	if err != nil {
		return nil, ErrAuthentication
	}
	defer clear(header)
	key, generation, err := deriveHeaderKey(header, credential)
	if err != nil {
		return nil, ErrAuthentication
	}
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, ErrAuthentication
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrAuthentication
	}
	payload, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil || len(payload) > maxPayload {
		clear(payload)
		return nil, ErrAuthentication
	}
	defer clear(payload)
	entries, err := parsePayload(payload)
	if err != nil {
		return nil, ErrAuthentication
	}
	vault := &Vault{entries: entries, generation: generation}
	return vault, nil
}

func EncodePortable(encoded []byte) string {
	return "gtgv1:" + base64.RawURLEncoding.EncodeToString(encoded)
}

func DecodePortable(value string) ([]byte, error) {
	if len(value) < 7 || value[:6] != "gtgv1:" {
		return nil, ErrAuthentication
	}
	out, err := base64.RawURLEncoding.DecodeString(value[6:])
	if err != nil || len(out) == 0 {
		clear(out)
		return nil, ErrAuthentication
	}
	return out, nil
}

func Rotate(encoded []byte, oldCredential, newCredential Credential) ([]byte, error) {
	vault, err := Open(encoded, oldCredential)
	if err != nil {
		return nil, err
	}
	defer vault.Destroy()
	return vault.Marshal(newCredential)
}

func (x *Vault) payload() ([]byte, uint64, error) {
	if x == nil {
		return nil, 0, ErrDestroyed
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.destroyed {
		return nil, 0, ErrDestroyed
	}
	names := make([]string, 0, len(x.entries))
	for name := range x.entries {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []byte
	out = appendTLV(out, 1, []byte{payloadVersion})
	for _, name := range names {
		secret := x.entries[name]
		data, err := secret.Bytes()
		if err != nil {
			clear(out)
			return nil, 0, err
		}
		value := make([]byte, 2+len(name)+len(data))
		binary.LittleEndian.PutUint16(value[:2], uint16(len(name)))
		copy(value[2:], name)
		copy(value[2+len(name):], data)
		clear(data)
		out = appendTLV(out, 16, value)
		clear(value)
	}
	if len(out) > maxPayload {
		clear(out)
		return nil, 0, ErrSecret
	}
	return out, x.generation, nil
}

func newHeader(credential Credential, generation uint64, random io.Reader) ([]byte, [32]byte, error) {
	var key [32]byte
	header := make([]byte, 0, 128)
	header = appendTLV(header, 1, []byte{byte(credential.Mode)})
	var generationBytes [8]byte
	binary.LittleEndian.PutUint64(generationBytes[:], generation)
	header = appendTLV(header, 2, generationBytes[:])
	clear(generationBytes[:])
	switch credential.Mode {
	case RawKey, MachineKey:
		if len(credential.Key) != 32 {
			clear(header)
			return nil, key, ErrCredential
		}
		copy(key[:], credential.Key)
		header = appendTLV(header, 3, []byte{0})
	case Passphrase:
		if len(credential.Passphrase) == 0 || !validKDF(credential.KDF) {
			clear(header)
			return nil, key, ErrCredential
		}
		var salt [16]byte
		if _, err := io.ReadFull(random, salt[:]); err != nil {
			clear(header)
			return nil, key, err
		}
		header = appendTLV(header, 3, []byte{byte(credential.KDF.Algorithm)})
		header = appendTLV(header, 4, salt[:])
		header = appendTLV(header, 5, encodeParameters(credential.KDF))
		derived, err := derivePassphrase(credential.Passphrase, salt[:], credential.KDF)
		clear(salt[:])
		if err != nil {
			clear(header)
			return nil, key, ErrCredential
		}
		key = derived
	default:
		clear(header)
		return nil, key, ErrCredential
	}
	if len(header) > maxHeader {
		clear(header)
		clear(key[:])
		return nil, key, ErrCredential
	}
	return header, key, nil
}

func deriveHeaderKey(header []byte, credential Credential) ([32]byte, uint64, error) {
	var key [32]byte
	fields, err := parseTLV(header)
	if err != nil {
		return key, 0, err
	}
	modeValue, ok := fields.one(1)
	if !ok || len(modeValue) != 1 || KeyMode(modeValue[0]) != credential.Mode {
		return key, 0, ErrCredential
	}
	generationValue, ok := fields.one(2)
	if !ok || len(generationValue) != 8 {
		return key, 0, ErrCredential
	}
	generation := binary.LittleEndian.Uint64(generationValue)
	algorithmValue, ok := fields.one(3)
	if !ok || len(algorithmValue) != 1 {
		return key, 0, ErrCredential
	}
	switch credential.Mode {
	case RawKey, MachineKey:
		if algorithmValue[0] != 0 || len(credential.Key) != 32 {
			return key, 0, ErrCredential
		}
		copy(key[:], credential.Key)
	case Passphrase:
		if len(credential.Passphrase) == 0 || algorithmValue[0] == 0 {
			return key, 0, ErrCredential
		}
		salt, saltOK := fields.one(4)
		parameters, parametersOK := fields.one(5)
		if !saltOK || len(salt) != 16 || !parametersOK {
			return key, 0, ErrCredential
		}
		config, err := decodeParameters(KDF(algorithmValue[0]), parameters)
		if err != nil {
			return key, 0, err
		}
		derived, err := derivePassphrase(credential.Passphrase, salt, config)
		if err != nil {
			return key, 0, err
		}
		key = derived
	default:
		return key, 0, ErrCredential
	}
	return key, generation, nil
}

func derivePassphrase(passphrase, salt []byte, parameters KDFParameters) ([32]byte, error) {
	var out [32]byte
	if !validKDF(parameters) {
		return out, ErrCredential
	}
	switch parameters.Algorithm {
	case Argon2id:
		derived := argon2.IDKey(passphrase, salt, parameters.Time, parameters.MemoryKiB, parameters.Threads, 32)
		copy(out[:], derived)
		clear(derived)
	case PBKDF2SHA256:
		derived := pbkdf2.Key(passphrase, salt, int(parameters.Iterations), 32, sha256.New)
		copy(out[:], derived)
		clear(derived)
	default:
		return out, ErrCredential
	}
	return out, nil
}

func validKDF(parameters KDFParameters) bool {
	switch parameters.Algorithm {
	case Argon2id:
		return parameters.Time >= 1 && parameters.Time <= 10 && parameters.MemoryKiB >= 8*1024 && parameters.MemoryKiB <= 256*1024 && parameters.Threads >= 1 && parameters.Threads <= 16
	case PBKDF2SHA256:
		return parameters.Iterations >= 100000 && parameters.Iterations <= 5000000
	default:
		return false
	}
}

func encodeParameters(parameters KDFParameters) []byte {
	var out [13]byte
	binary.LittleEndian.PutUint32(out[:4], parameters.Time)
	binary.LittleEndian.PutUint32(out[4:8], parameters.MemoryKiB)
	out[8] = parameters.Threads
	binary.LittleEndian.PutUint32(out[9:13], parameters.Iterations)
	return out[:]
}

func decodeParameters(algorithm KDF, data []byte) (KDFParameters, error) {
	if len(data) != 13 {
		return KDFParameters{}, ErrCredential
	}
	parameters := KDFParameters{
		Algorithm:  algorithm,
		Time:       binary.LittleEndian.Uint32(data[:4]),
		MemoryKiB:  binary.LittleEndian.Uint32(data[4:8]),
		Threads:    data[8],
		Iterations: binary.LittleEndian.Uint32(data[9:13]),
	}
	if !validKDF(parameters) {
		return KDFParameters{}, ErrCredential
	}
	return parameters, nil
}

func parseEnvelope(encoded []byte) ([]byte, []byte, []byte, []byte, error) {
	if len(encoded) < 8+12+16 || !bytes.Equal(encoded[:4], []byte(formatMagic)) || binary.LittleEndian.Uint16(encoded[4:6]) != formatVersion {
		return nil, nil, nil, nil, ErrAuthentication
	}
	headerLength := int(binary.LittleEndian.Uint16(encoded[6:8]))
	if headerLength < 1 || headerLength > maxHeader || len(encoded) < 8+headerLength+12+16 {
		return nil, nil, nil, nil, ErrAuthentication
	}
	header := append([]byte(nil), encoded[8:8+headerLength]...)
	nonce := encoded[8+headerLength : 8+headerLength+12]
	ciphertext := encoded[8+headerLength+12:]
	aad := encoded[:8+headerLength]
	return header, nonce, ciphertext, aad, nil
}

func parsePayload(payload []byte) (map[string]*Secret, error) {
	fields, err := parseTLV(payload)
	if err != nil {
		return nil, err
	}
	version, ok := fields.one(1)
	if !ok || len(version) != 1 {
		return nil, ErrSecret
	}
	recordType := byte(16)
	switch version[0] {
	case 0:
		recordType = 17
	case payloadVersion:
	default:
		return nil, ErrSecret
	}
	entries := make(map[string]*Secret)
	for _, value := range fields.multi(recordType) {
		if err := addEntry(entries, value); err != nil {
			destroyEntries(entries)
			return nil, err
		}
	}
	return entries, nil
}

func addEntry(entries map[string]*Secret, value []byte) error {
	if len(value) < 3 {
		return ErrSecret
	}
	nameLength := int(binary.LittleEndian.Uint16(value[:2]))
	if nameLength == 0 || 2+nameLength >= len(value) {
		return ErrSecret
	}
	name := string(value[2 : 2+nameLength])
	if !validName(name) {
		return ErrSecret
	}
	if _, exists := entries[name]; exists {
		return ErrSecret
	}
	secret, err := NewSecret(value[2+nameLength:])
	if err != nil {
		return err
	}
	entries[name] = secret
	return nil
}

type tlvFields map[byte][][]byte

func (x tlvFields) one(kind byte) ([]byte, bool) {
	values := x[kind]
	if len(values) != 1 {
		return nil, false
	}
	return values[0], true
}

func (x tlvFields) multi(kind byte) [][]byte {
	return x[kind]
}

func parseTLV(data []byte) (tlvFields, error) {
	fields := make(tlvFields)
	for len(data) > 0 {
		if len(data) < 3 {
			return nil, ErrSecret
		}
		kind := data[0]
		length := int(binary.LittleEndian.Uint16(data[1:3]))
		data = data[3:]
		if length > len(data) {
			return nil, ErrSecret
		}
		fields[kind] = append(fields[kind], data[:length])
		data = data[length:]
	}
	return fields, nil
}

func appendTLV(dst []byte, kind byte, value []byte) []byte {
	if len(value) > 65535 {
		return nil
	}
	dst = append(dst, kind, 0, 0)
	binary.LittleEndian.PutUint16(dst[len(dst)-2:], uint16(len(value)))
	return append(dst, value...)
}

func destroyEntries(entries map[string]*Secret) {
	for name, secret := range entries {
		secret.Destroy()
		delete(entries, name)
	}
}

func validName(name string) bool {
	return len(name) > 0 && len(name) <= 1024
}
