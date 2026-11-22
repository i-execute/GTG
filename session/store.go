package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

var ErrStore = errors.New("gtg: session store rejected")
var ErrStoreAuthentication = errors.New("gtg: session store authentication failed")
var ErrStoreDestroyed = errors.New("gtg: session store destroyed")

const (
	storeMagic        = "GTS2"
	storeVersion      = 2
	storeSaltSize     = 16
	storeNonceSize    = 12
	storeMaxRecords   = 1024
	storeMaxPayload   = 64 << 20
	storeMaxName      = 128
	storeMetaName     = "@active"
	storeLockWait     = 10 * time.Second
	storeLockInterval = 25 * time.Millisecond
)

type AccountKind uint8

const (
	UserAccount AccountKind = iota + 1
	BotAccount
)

type KDFParameters struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

type Credential struct {
	Password []byte
	RawKey   []byte
	Machine  []byte
	KDF      KDFParameters
}

type DC struct {
	ID      int32  `json:"id"`
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

type Peer struct {
	ID         int64  `json:"id"`
	AccessHash int64  `json:"access_hash"`
	Kind       string `json:"kind"`
}

type Updates struct {
	PTS      int32           `json:"pts"`
	QTS      int32           `json:"qts"`
	Seq      int32           `json:"seq"`
	Date     int32           `json:"date"`
	Channels map[int64]int32 `json:"channels"`
}

type Account struct {
	Kind       AccountKind `json:"kind"`
	Test       bool        `json:"test"`
	DCID       int32       `json:"dc_id"`
	DCs        []DC        `json:"dcs"`
	AuthKey    []byte      `json:"auth_key"`
	AuthKeyID  [8]byte     `json:"auth_key_id"`
	ServerSalt [8]byte     `json:"server_salt"`
	TimeOffset int64       `json:"time_offset"`
	UserID     int64       `json:"user_id"`
	APIID      int32       `json:"api_id"`
	BotToken   []byte      `json:"bot_token"`
	Layer      int32       `json:"layer"`
	Peers      []Peer      `json:"peers"`
	Updates    Updates     `json:"updates"`
}

type Store struct {
	mu        sync.RWMutex
	accounts  map[string]Account
	active    string
	destroyed bool
}

type storeHeader struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
	Salt      [storeSaltSize]byte
}

type storeFrame struct {
	Name       string
	Kind       AccountKind
	Salt       [storeSaltSize]byte
	Nonce      [storeNonceSize]byte
	Ciphertext []byte
}

type storeMeta struct {
	Active string `json:"active"`
}

func DefaultKDF() KDFParameters {
	return KDFParameters{Time: 3, MemoryKiB: 65536, Threads: 1}
}

func NewPasswordCredential(password []byte, parameters KDFParameters) (Credential, error) {
	if len(password) == 0 || !validKDF(parameters) {
		return Credential{}, ErrStore
	}
	return Credential{Password: append([]byte(nil), password...), KDF: parameters}, nil
}

func NewRawCredential(key []byte) (Credential, error) {
	if len(key) != 32 {
		return Credential{}, ErrStore
	}
	return Credential{RawKey: append([]byte(nil), key...), KDF: DefaultKDF()}, nil
}

func NewMachineCredential(key, machine []byte) (Credential, error) {
	if len(key) != 32 || len(machine) == 0 || len(machine) > 4096 {
		return Credential{}, ErrStore
	}
	return Credential{RawKey: append([]byte(nil), key...), Machine: append([]byte(nil), machine...), KDF: DefaultKDF()}, nil
}

func (x *Credential) Destroy() {
	if x == nil {
		return
	}
	clear(x.Password)
	clear(x.RawKey)
	clear(x.Machine)
	*x = Credential{}
}

func NewStore() *Store {
	return &Store{accounts: make(map[string]Account)}
}

func (x *Store) Put(name string, account Account) error {
	if x == nil {
		return ErrStoreDestroyed
	}
	if !validStoreName(name) || !validAccount(account) {
		return ErrStore
	}
	copyAccount := cloneAccount(account)
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.destroyed {
		copyAccount.Destroy()
		return ErrStoreDestroyed
	}
	previous, exists := x.accounts[name]
	x.accounts[name] = copyAccount
	if !exists && x.active == "" {
		x.active = name
	}
	previous.Destroy()
	return nil
}

func (x *Store) Get(name string) (Account, error) {
	if x == nil {
		return Account{}, ErrStoreDestroyed
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.destroyed {
		return Account{}, ErrStoreDestroyed
	}
	account, ok := x.accounts[name]
	if !ok {
		return Account{}, ErrStore
	}
	return cloneAccount(account), nil
}

func (x *Store) Delete(name string) error {
	if x == nil {
		return ErrStoreDestroyed
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.destroyed {
		return ErrStoreDestroyed
	}
	account, ok := x.accounts[name]
	if !ok {
		return ErrStore
	}
	delete(x.accounts, name)
	account.Destroy()
	if x.active == name {
		x.active = ""
		for candidate := range x.accounts {
			x.active = candidate
			break
		}
	}
	return nil
}

func (x *Store) Activate(name string) error {
	if x == nil {
		return ErrStoreDestroyed
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.destroyed {
		return ErrStoreDestroyed
	}
	if _, ok := x.accounts[name]; !ok {
		return ErrStore
	}
	x.active = name
	return nil
}

func (x *Store) Active() (string, Account, error) {
	if x == nil {
		return "", Account{}, ErrStoreDestroyed
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.destroyed {
		return "", Account{}, ErrStoreDestroyed
	}
	account, ok := x.accounts[x.active]
	if !ok || x.active == "" {
		return "", Account{}, ErrStore
	}
	return x.active, cloneAccount(account), nil
}

func (x *Store) Names() ([]string, error) {
	if x == nil {
		return nil, ErrStoreDestroyed
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.destroyed {
		return nil, ErrStoreDestroyed
	}
	out := make([]string, 0, len(x.accounts))
	for name := range x.accounts {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func (x *Store) Destroy() {
	if x == nil {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.destroyed {
		return
	}
	for name, account := range x.accounts {
		account.Destroy()
		delete(x.accounts, name)
	}
	x.active = ""
	x.destroyed = true
}

func (x Account) Destroy() {
	clear(x.AuthKey)
	clear(x.BotToken)
	clear(x.DCs)
	clear(x.Peers)
	clear(x.AuthKeyID[:])
	clear(x.ServerSalt[:])
	for channel := range x.Updates.Channels {
		delete(x.Updates.Channels, channel)
	}
}

func (x *Store) Marshal(credential Credential) ([]byte, error) {
	if x == nil {
		return nil, ErrStoreDestroyed
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.destroyed || len(x.accounts) == 0 || x.active == "" || !validCredential(credential) {
		return nil, ErrStore
	}
	header, root, err := newStoreHeader(credential)
	if err != nil {
		return nil, err
	}
	defer clear(root)
	frames := make([]storeFrame, 0, len(x.accounts)+1)
	meta, err := json.Marshal(storeMeta{Active: x.active})
	if err != nil {
		return nil, ErrStore
	}
	frame, err := sealFrame(root, header, storeMetaName, 0, meta)
	clear(meta)
	if err != nil {
		return nil, err
	}
	frames = append(frames, frame)
	names := make([]string, 0, len(x.accounts))
	for name := range x.accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		account := x.accounts[name]
		plain, err := json.Marshal(account)
		if err != nil {
			clearFrames(frames)
			return nil, ErrStore
		}
		frame, err := sealFrame(root, header, name, account.Kind, plain)
		clear(plain)
		if err != nil {
			clearFrames(frames)
			return nil, err
		}
		frames = append(frames, frame)
	}
	out, err := encodeStore(header, frames)
	clearFrames(frames)
	if err != nil {
		clear(out)
		return nil, err
	}
	return out, nil
}

func OpenStore(encoded []byte, credential Credential) (*Store, error) {
	header, frames, err := decodeStore(encoded)
	if err != nil || !validCredential(credential) {
		clearFrames(frames)
		return nil, ErrStoreAuthentication
	}
	defer clearFrames(frames)
	root, err := deriveRoot(credential, header)
	if err != nil {
		return nil, ErrStoreAuthentication
	}
	defer clear(root)
	out := NewStore()
	for _, frame := range frames {
		plain, err := openFrame(root, header, frame)
		if err != nil {
			out.Destroy()
			return nil, ErrStoreAuthentication
		}
		if frame.Name == storeMetaName {
			var meta storeMeta
			err = json.Unmarshal(plain, &meta)
			clear(plain)
			if frame.Kind != 0 || err != nil || !validStoreName(meta.Active) {
				out.Destroy()
				return nil, ErrStoreAuthentication
			}
			out.active = meta.Active
			continue
		}
		var account Account
		err = json.Unmarshal(plain, &account)
		clear(plain)
		if err != nil || account.Kind != frame.Kind || !validStoreName(frame.Name) || !validAccount(account) {
			account.Destroy()
			out.Destroy()
			return nil, ErrStoreAuthentication
		}
		if _, exists := out.accounts[frame.Name]; exists {
			account.Destroy()
			out.Destroy()
			return nil, ErrStoreAuthentication
		}
		out.accounts[frame.Name] = account
	}
	if len(out.accounts) == 0 || out.active == "" {
		out.Destroy()
		return nil, ErrStoreAuthentication
	}
	if _, ok := out.accounts[out.active]; !ok {
		out.Destroy()
		return nil, ErrStoreAuthentication
	}
	return out, nil
}

func EncodePortable(encoded []byte) string {
	return "gtgs2:" + base64.RawURLEncoding.EncodeToString(encoded)
}

func DecodePortable(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "gtgs2:") {
		return nil, ErrStoreAuthentication
	}
	out, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "gtgs2:"))
	if err != nil || len(out) == 0 || len(out) > storeMaxPayload {
		clear(out)
		return nil, ErrStoreAuthentication
	}
	return out, nil
}

func SaveFile(path string, source *Store, credential Credential) error {
	if path == "" || source == nil {
		return ErrStore
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return withStoreLock(path, func() error {
		encoded, err := source.Marshal(credential)
		if err != nil {
			return err
		}
		defer clear(encoded)
		return writeAtomic(path, encoded)
	})
}

func LoadFile(path string, credential Credential) (*Store, error) {
	if path == "" {
		return nil, ErrStoreAuthentication
	}
	var out *Store
	err := withStoreLock(path, func() error {
		encoded, err := os.ReadFile(path)
		if err != nil {
			return ErrStoreAuthentication
		}
		defer clear(encoded)
		out, err = OpenStore(encoded, credential)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func RotateFile(path string, oldCredential, newCredential Credential) error {
	store, err := LoadFile(path, oldCredential)
	if err != nil {
		return err
	}
	defer store.Destroy()
	return SaveFile(path, store, newCredential)
}

func ImportTelethon(value string, apiID int32, token []byte) (Account, error) {
	parsed, err := ParseTelethon(value)
	if err != nil {
		return Account{}, err
	}
	defer parsed.Destroy()
	kind := UserAccount
	if len(token) != 0 {
		kind = BotAccount
	}
	return Account{Kind: kind, DCID: parsed.DCID, DCs: []DC{{ID: parsed.DCID, Address: parsed.Address, Port: parsed.Port}}, AuthKey: append([]byte(nil), parsed.AuthKey...), APIID: apiID, BotToken: append([]byte(nil), token...), Updates: Updates{Channels: make(map[int64]int32)}}, nil
}

func ExportTelethon(account Account) (string, error) {
	endpoint, ok := accountEndpoint(account)
	if !ok {
		return "", ErrStore
	}
	value := Telethon{DCID: account.DCID, Address: endpoint.Address, Port: endpoint.Port, AuthKey: append([]byte(nil), account.AuthKey...)}
	defer value.Destroy()
	return value.String()
}

func ParsePyrogram(value string) (Account, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(value)
		if err != nil {
			return Account{}, ErrStore
		}
	}
	defer clear(decoded)
	if len(decoded) != 271 || decoded[0] == 0 {
		return Account{}, ErrStore
	}
	apiID := int32(binary.BigEndian.Uint32(decoded[1:5]))
	if apiID <= 0 || decoded[5] > 1 || decoded[270] > 1 {
		return Account{}, ErrStore
	}
	account := Account{Kind: UserAccount, Test: decoded[5] == 1, DCID: int32(decoded[0]), APIID: apiID, AuthKey: append([]byte(nil), decoded[6:262]...), UserID: int64(binary.BigEndian.Uint64(decoded[262:270])), Updates: Updates{Channels: make(map[int64]int32)}}
	if decoded[270] == 1 {
		account.Kind = BotAccount
	}
	if !validAccount(account) {
		account.Destroy()
		return Account{}, ErrStore
	}
	return account, nil
}

func (x Account) PyrogramString() (string, error) {
	if !validAccount(x) || x.DCID > 255 || x.APIID <= 0 {
		return "", ErrStore
	}
	out := make([]byte, 271)
	out[0] = byte(x.DCID)
	binary.BigEndian.PutUint32(out[1:5], uint32(x.APIID))
	if x.Test {
		out[5] = 1
	}
	copy(out[6:262], x.AuthKey)
	binary.BigEndian.PutUint64(out[262:270], uint64(x.UserID))
	if x.Kind == BotAccount {
		out[270] = 1
	}
	value := base64.RawURLEncoding.EncodeToString(out)
	clear(out)
	return value, nil
}

func cloneAccount(value Account) Account {
	out := value
	out.AuthKey = append([]byte(nil), value.AuthKey...)
	out.BotToken = append([]byte(nil), value.BotToken...)
	out.DCs = append([]DC(nil), value.DCs...)
	out.Peers = append([]Peer(nil), value.Peers...)
	out.Updates.Channels = make(map[int64]int32, len(value.Updates.Channels))
	for channel, pts := range value.Updates.Channels {
		out.Updates.Channels[channel] = pts
	}
	return out
}

func validAccount(value Account) bool {
	if value.Kind != UserAccount && value.Kind != BotAccount || value.DCID <= 0 || len(value.AuthKey) != 256 || value.APIID < 0 || len(value.BotToken) > 4096 || len(value.DCs) > 64 || len(value.Peers) > 1<<20 {
		return false
	}
	if value.Kind == BotAccount && len(value.BotToken) == 0 {
		return false
	}
	for _, endpoint := range value.DCs {
		if endpoint.ID <= 0 || endpoint.Address == "" || len(endpoint.Address) > 255 || endpoint.Port == 0 {
			return false
		}
	}
	return true
}

func accountEndpoint(value Account) (DC, bool) {
	for _, endpoint := range value.DCs {
		if endpoint.ID == value.DCID {
			return endpoint, true
		}
	}
	return DC{}, false
}

func validStoreName(value string) bool {
	return value != "" && len(value) <= storeMaxName && value != storeMetaName && !strings.ContainsAny(value, "\x00/\\")
}

func validKDF(value KDFParameters) bool {
	return value.Time >= 1 && value.Time <= 10 && value.MemoryKiB >= 8192 && value.MemoryKiB <= 1048576 && value.Threads >= 1 && value.Threads <= 32
}

func validCredential(value Credential) bool {
	if !validKDF(value.KDF) || len(value.Machine) > 4096 {
		return false
	}
	return len(value.Password) > 0 && len(value.RawKey) == 0 && len(value.Machine) == 0 || len(value.Password) == 0 && len(value.RawKey) == 32
}

func newStoreHeader(credential Credential) (storeHeader, []byte, error) {
	var header storeHeader
	if !validCredential(credential) {
		return header, nil, ErrStore
	}
	header.Time = credential.KDF.Time
	header.MemoryKiB = credential.KDF.MemoryKiB
	header.Threads = credential.KDF.Threads
	if _, err := io.ReadFull(rand.Reader, header.Salt[:]); err != nil {
		return storeHeader{}, nil, err
	}
	root, err := deriveRoot(credential, header)
	return header, root, err
}

func deriveRoot(credential Credential, header storeHeader) ([]byte, error) {
	if !validCredential(credential) || !validKDF(KDFParameters{Time: header.Time, MemoryKiB: header.MemoryKiB, Threads: header.Threads}) {
		return nil, ErrStoreAuthentication
	}
	if len(credential.Password) != 0 {
		return argon2.IDKey(credential.Password, header.Salt[:], header.Time, header.MemoryKiB, header.Threads, 32), nil
	}
	material := append([]byte(nil), credential.RawKey...)
	material = append(material, credential.Machine...)
	defer clear(material)
	reader := hkdf.New(sha256.New, material, header.Salt[:], []byte("gtg/session/root/v2"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(reader, out); err != nil {
		clear(out)
		return nil, ErrStoreAuthentication
	}
	return out, nil
}

func sealFrame(root []byte, header storeHeader, name string, kind AccountKind, plain []byte) (storeFrame, error) {
	var frame storeFrame
	if len(root) != 32 || len(plain) > storeMaxPayload || name == "" {
		return frame, ErrStore
	}
	frame.Name = name
	frame.Kind = kind
	if _, err := io.ReadFull(rand.Reader, frame.Salt[:]); err != nil {
		return storeFrame{}, err
	}
	if _, err := io.ReadFull(rand.Reader, frame.Nonce[:]); err != nil {
		return storeFrame{}, err
	}
	key, err := deriveFrameKey(root, frame.Salt[:], name)
	if err != nil {
		return storeFrame{}, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return storeFrame{}, ErrStore
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return storeFrame{}, ErrStore
	}
	aad := frameAAD(header, frame)
	defer clear(aad)
	frame.Ciphertext = aead.Seal(nil, frame.Nonce[:], plain, aad)
	return frame, nil
}

func openFrame(root []byte, header storeHeader, frame storeFrame) ([]byte, error) {
	if len(root) != 32 || len(frame.Ciphertext) < 16 || len(frame.Ciphertext) > storeMaxPayload+16 || frame.Name == "" {
		return nil, ErrStoreAuthentication
	}
	key, err := deriveFrameKey(root, frame.Salt[:], frame.Name)
	if err != nil {
		return nil, ErrStoreAuthentication
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrStoreAuthentication
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrStoreAuthentication
	}
	aad := frameAAD(header, frame)
	defer clear(aad)
	plain, err := aead.Open(nil, frame.Nonce[:], frame.Ciphertext, aad)
	if err != nil || len(plain) > storeMaxPayload {
		clear(plain)
		return nil, ErrStoreAuthentication
	}
	return plain, nil
}

func deriveFrameKey(root, salt []byte, name string) ([]byte, error) {
	reader := hkdf.New(sha256.New, root, salt, append([]byte("gtg/session/record/v2/"), name...))
	out := make([]byte, 32)
	if _, err := io.ReadFull(reader, out); err != nil {
		clear(out)
		return nil, err
	}
	return out, nil
}

func frameAAD(header storeHeader, frame storeFrame) []byte {
	out := make([]byte, 0, 4+1+4+4+1+storeSaltSize+2+len(frame.Name)+1+storeSaltSize+storeNonceSize)
	out = append(out, storeMagic...)
	out = append(out, storeVersion)
	var parameters [9]byte
	binary.LittleEndian.PutUint32(parameters[:4], header.Time)
	binary.LittleEndian.PutUint32(parameters[4:8], header.MemoryKiB)
	parameters[8] = header.Threads
	out = append(out, parameters[:]...)
	out = append(out, header.Salt[:]...)
	var length [2]byte
	binary.LittleEndian.PutUint16(length[:], uint16(len(frame.Name)))
	out = append(out, length[:]...)
	out = append(out, frame.Name...)
	out = append(out, byte(frame.Kind))
	out = append(out, frame.Salt[:]...)
	out = append(out, frame.Nonce[:]...)
	clear(parameters[:])
	clear(length[:])
	return out
}

func encodeStore(header storeHeader, frames []storeFrame) ([]byte, error) {
	if len(frames) < 2 || len(frames) > storeMaxRecords+1 {
		return nil, ErrStore
	}
	out := make([]byte, 0, 64)
	out = append(out, storeMagic...)
	out = append(out, storeVersion)
	var parameters [11]byte
	binary.LittleEndian.PutUint32(parameters[:4], header.Time)
	binary.LittleEndian.PutUint32(parameters[4:8], header.MemoryKiB)
	parameters[8] = header.Threads
	binary.LittleEndian.PutUint16(parameters[9:11], uint16(len(frames)))
	out = append(out, parameters[:]...)
	out = append(out, header.Salt[:]...)
	for _, frame := range frames {
		if len(frame.Name) == 0 || len(frame.Name) > storeMaxName || len(frame.Ciphertext) < 16 || len(frame.Ciphertext) > storeMaxPayload+16 {
			clear(out)
			return nil, ErrStore
		}
		var prefix [7]byte
		binary.LittleEndian.PutUint16(prefix[:2], uint16(len(frame.Name)))
		prefix[2] = byte(frame.Kind)
		binary.LittleEndian.PutUint32(prefix[3:7], uint32(len(frame.Ciphertext)))
		out = append(out, prefix[:]...)
		out = append(out, frame.Name...)
		out = append(out, frame.Salt[:]...)
		out = append(out, frame.Nonce[:]...)
		out = append(out, frame.Ciphertext...)
		clear(prefix[:])
	}
	clear(parameters[:])
	return out, nil
}

func decodeStore(encoded []byte) (storeHeader, []storeFrame, error) {
	var header storeHeader
	if len(encoded) < 4+1+11+storeSaltSize || !bytes.Equal(encoded[:4], []byte(storeMagic)) || encoded[4] != storeVersion {
		return header, nil, ErrStoreAuthentication
	}
	header.Time = binary.LittleEndian.Uint32(encoded[5:9])
	header.MemoryKiB = binary.LittleEndian.Uint32(encoded[9:13])
	header.Threads = encoded[13]
	count := int(binary.LittleEndian.Uint16(encoded[14:16]))
	copy(header.Salt[:], encoded[16:16+storeSaltSize])
	if !validKDF(KDFParameters{Time: header.Time, MemoryKiB: header.MemoryKiB, Threads: header.Threads}) || count < 2 || count > storeMaxRecords+1 {
		return storeHeader{}, nil, ErrStoreAuthentication
	}
	offset := 16 + storeSaltSize
	frames := make([]storeFrame, 0, count)
	for index := 0; index < count; index++ {
		if len(encoded)-offset < 7 {
			clearFrames(frames)
			return storeHeader{}, nil, ErrStoreAuthentication
		}
		nameLength := int(binary.LittleEndian.Uint16(encoded[offset : offset+2]))
		kind := AccountKind(encoded[offset+2])
		cipherLength := int(binary.LittleEndian.Uint32(encoded[offset+3 : offset+7]))
		offset += 7
		if nameLength == 0 || nameLength > storeMaxName || cipherLength < 16 || cipherLength > storeMaxPayload+16 || len(encoded)-offset < nameLength+storeSaltSize+storeNonceSize+cipherLength {
			clearFrames(frames)
			return storeHeader{}, nil, ErrStoreAuthentication
		}
		frame := storeFrame{Name: string(encoded[offset : offset+nameLength]), Kind: kind}
		offset += nameLength
		copy(frame.Salt[:], encoded[offset:offset+storeSaltSize])
		offset += storeSaltSize
		copy(frame.Nonce[:], encoded[offset:offset+storeNonceSize])
		offset += storeNonceSize
		frame.Ciphertext = append([]byte(nil), encoded[offset:offset+cipherLength]...)
		offset += cipherLength
		frames = append(frames, frame)
	}
	if offset != len(encoded) {
		clearFrames(frames)
		return storeHeader{}, nil, ErrStoreAuthentication
	}
	return header, frames, nil
}

func clearFrames(frames []storeFrame) {
	for index := range frames {
		clear(frames[index].Ciphertext)
		clear(frames[index].Salt[:])
		clear(frames[index].Nonce[:])
		frames[index] = storeFrame{}
	}
}

func withStoreLock(path string, run func() error) error {
	lock := path + ".lock"
	deadline := time.Now().Add(storeLockWait)
	for {
		file, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			_ = file.Close()
			defer os.Remove(lock)
			return run()
		}
		if !errors.Is(err, os.ErrExist) || time.Now().After(deadline) {
			return ErrStore
		}
		time.Sleep(storeLockInterval)
	}
}

func writeAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".gtg-session-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err == nil {
		_ = directoryFile.Sync()
		_ = directoryFile.Close()
	}
	return nil
}
