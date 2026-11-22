package session

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestStoreRoundTripAndRotation(t *testing.T) {
	store := fixtureStore(t)
	defer store.Destroy()
	password, err := NewPasswordCredential([]byte("correct horse battery staple"), KDFParameters{Time: 1, MemoryKiB: 8192, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer password.Destroy()
	encoded, err := store.Marshal(password)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	opened, err := OpenStore(encoded, password)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Destroy()
	name, account, err := opened.Active()
	if err != nil {
		t.Fatal(err)
	}
	defer account.Destroy()
	if name != "bot" || account.Kind != BotAccount || account.UserID != 77 || len(account.AuthKey) != 256 || len(account.BotToken) == 0 {
		t.Fatal("active account mismatch")
	}
	raw, err := NewRawCredential(bytesOf(3, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Destroy()
	tamperSource, err := store.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(tamperSource)
	for index := range tamperSource {
		modified := append([]byte(nil), tamperSource...)
		modified[index] ^= 0x80
		candidate, err := OpenStore(modified, raw)
		clear(modified)
		if candidate != nil {
			candidate.Destroy()
		}
		if !errors.Is(err, ErrStoreAuthentication) {
			t.Fatalf("tamper offset %d returned %v", index, err)
		}
	}
	portable := EncodePortable(encoded)
	decoded, err := DecodePortable(portable)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(encoded) {
		t.Fatal("portable mismatch")
	}
	clear(decoded)
}

func TestStoreFileConcurrentAndPermissions(t *testing.T) {
	store := fixtureStore(t)
	defer store.Destroy()
	first, err := NewRawCredential(bytesOf(11, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()
	second, err := NewMachineCredential(bytesOf(19, 32), []byte("machine-material"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	path := filepath.Join(t.TempDir(), "cell", "session.gtgs")
	if err := SaveFile(path, store, first); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for index := 0; index < 4; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := SaveFile(path, store, first); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	if err := RotateFile(path, first, second); err != nil {
		t.Fatal(err)
	}
	opened, err := LoadFile(path, second)
	if err != nil {
		t.Fatal(err)
	}
	opened.Destroy()
	if _, err := LoadFile(path, first); !errors.Is(err, ErrStoreAuthentication) {
		t.Fatalf("old credential result=%v", err)
	}
}

func TestPyrogramAndTelethonRoundTrip(t *testing.T) {
	account := fixtureAccount(UserAccount)
	account.DCs = []DC{{ID: account.DCID, Address: "149.154.167.50", Port: 443}}
	defer account.Destroy()
	pyrogram, err := account.PyrogramString()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePyrogram(pyrogram)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	if parsed.DCID != account.DCID || parsed.APIID != account.APIID || parsed.UserID != account.UserID || string(parsed.AuthKey) != string(account.AuthKey) {
		t.Fatal("pyrogram mismatch")
	}
	telethon, err := ExportTelethon(account)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := ImportTelethon(telethon, account.APIID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer imported.Destroy()
	if imported.DCID != account.DCID || string(imported.AuthKey) != string(account.AuthKey) || len(imported.DCs) != 1 {
		t.Fatal("telethon mismatch")
	}
}

func FuzzStoreOpen(f *testing.F) {
	store := NewStore()
	account := fixtureAccount(UserAccount)
	if err := store.Put("user", account); err != nil {
		f.Fatal(err)
	}
	account.Destroy()
	credential, err := NewRawCredential(bytesOf(7, 32))
	if err != nil {
		f.Fatal(err)
	}
	encoded, err := store.Marshal(credential)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	store.Destroy()
	credential.Destroy()
	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := NewRawCredential(bytesOf(7, 32))
		if err != nil {
			t.Fatal(err)
		}
		out, _ := OpenStore(data, value)
		if out != nil {
			out.Destroy()
		}
		value.Destroy()
	})
}

func fixtureStore(t *testing.T) *Store {
	t.Helper()
	store := NewStore()
	user := fixtureAccount(UserAccount)
	if err := store.Put("user", user); err != nil {
		t.Fatal(err)
	}
	user.Destroy()
	bot := fixtureAccount(BotAccount)
	if err := store.Put("bot", bot); err != nil {
		t.Fatal(err)
	}
	bot.Destroy()
	if err := store.Activate("bot"); err != nil {
		t.Fatal(err)
	}
	return store
}

func fixtureAccount(kind AccountKind) Account {
	key := bytesOf(byte(kind), 256)
	token := []byte(nil)
	if kind == BotAccount {
		token = []byte("not-a-real-token")
	}
	account := Account{Kind: kind, DCID: 2, DCs: []DC{{ID: 2, Address: "149.154.167.50", Port: 443}}, AuthKey: key, APIID: 12345, UserID: 77, BotToken: token, Layer: 233, Peers: []Peer{{ID: 10, AccessHash: 20, Kind: "user"}}, Updates: Updates{PTS: 1, QTS: 2, Seq: 3, Date: 4, Channels: map[int64]int32{10: 11}}}
	for index := range account.AuthKeyID {
		account.AuthKeyID[index] = byte(index + 1)
	}
	for index := range account.ServerSalt {
		account.ServerSalt[index] = byte(index + 9)
	}
	return account
}

func bytesOf(seed byte, length int) []byte {
	out := make([]byte, length)
	for index := range out {
		out[index] = seed + byte(index*17)
	}
	return out
}
