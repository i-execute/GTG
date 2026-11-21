package core

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"
)

func TestGCMNIST(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plain := make([]byte, 16)
	want := decode(t, "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
	gcm, err := NewGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 0, len(want))
	got, err := gcm.Seal(out, nonce, plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ciphertext mismatch\ngot  %x\nwant %x", got, want)
	}
	back, err := gcm.Open(make([]byte, 0, len(plain)), nonce, got, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatal("round-trip mismatch")
	}
	got[len(got)-1] ^= 1
	if _, err := gcm.Open(make([]byte, 0, len(plain)), nonce, got, nil); err == nil {
		t.Fatal("accepted altered tag")
	}
}

func TestPBKDF2LocalKey(t *testing.T) {
	key, err := DeriveLocalKey("password", []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key[:], make([]byte, 32)) {
		t.Fatal("zero key")
	}
	want := decode(t, "669cfe52482116fda1aa2cbe409b2f56c8e4563752b7a28f6eaab614ee005178")
	if !bytes.Equal(key[:], want) {
		t.Fatalf("derived key mismatch\ngot  %x\nwant %x", key, want)
	}
}

func TestMTProtoKDF(t *testing.T) {
	auth := makePattern(256, 0)
	plain := makePattern(64, 9)
	messageKey, err := MessageKey(auth, plain, ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(messageKey[:], make([]byte, 16)) {
		t.Fatal("zero message key")
	}
	key, iv, err := DeriveMessageAES(auth, messageKey[:], ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	ige, err := NewIGE(key[:])
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(plain))
	if err := ige.Encrypt(ciphertext, plain, iv[:]); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(plain))
	if err := ige.Decrypt(back, ciphertext, iv[:]); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatal("MTProto KDF IGE round-trip mismatch")
	}
	id, err := AuthorizationKeyID(auth)
	if err != nil {
		t.Fatal(err)
	}
	sum := sum256(auth)
	if bytes.Equal(id[:], sum[:8]) {
		t.Fatal("used wrong authorization key hash")
	}
}

func TestSRPVector(t *testing.T) {
	prime := decode(t, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
	salt1 := decode(t, "0102030405060708090a0b0c0d0e0f10")
	salt2 := decode(t, "1112131415161718191a1b1c1d1e1f20")
	publicB := decode(t, "42094e9ae99cb01bd2d68e52ff23ce062719ffd68327b7253382d0d2931209ef")
	privateA := decode(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	wantA := decode(t, "51ea1a644dbf0e74e5d48cf17e15d08b06a56d4e5523479f4b4455f18610f552")
	wantM1 := decode(t, "18032ae57a47f9c230a97d8cf6f2dc400ca1dcab453fc01b2221ad5a3a1495e1")
	proof, err := BuildSRPProof(SRPParameters{ID: 7, Generator: 5, Prime: prime, Salt1: salt1, Salt2: salt2, PublicB: publicB}, "correct horse battery staple", privateA)
	if err != nil {
		t.Fatal(err)
	}
	if proof.ID != 7 || !bytes.Equal(proof.A, wantA) || !bytes.Equal(proof.M1[:], wantM1) {
		t.Fatalf("SRP proof mismatch\nA  %x\nM1 %x", proof.A, proof.M1)
	}
}

func TestModExp(t *testing.T) {
	got, err := ModExp([]byte{5}, []byte{117}, []byte{19})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{1}) {
		t.Fatalf("got %x", got)
	}
}

func TestGCMErrors(t *testing.T) {
	gcm, err := NewGCM(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gcm.Seal(nil, make([]byte, 11), nil, nil); !errors.Is(err, ErrGCMNonceSize) {
		t.Fatal(err)
	}
	if _, err := gcm.Seal(make([]byte, 0, 15), make([]byte, 12), nil, nil); !errors.Is(err, ErrGCMDestination) {
		t.Fatal(err)
	}
}

func TestSHA256Reference(t *testing.T) {
	want := sha256.Sum256([]byte("abc"))
	got := sum256([]byte("a"), []byte("b"), []byte("c"))
	if got != want {
		t.Fatal("SHA-256 mismatch")
	}
}

func TestMTProtoSealOpen(t *testing.T) {
	auth := makePattern(256, 77)
	for _, direction := range []Direction{ClientToServer, ServerToClient} {
		box, err := NewMTProto(auth)
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range []int{0, 16, 64, 4096} {
			plain := makePattern(size, byte(size+3))
			messageKey, ciphertext, err := box.Seal(make([]byte, 0, size), plain, direction)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := box.Open(make([]byte, 0, size), messageKey[:], ciphertext, direction)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(opened, plain) {
				t.Fatalf("direction=%d size=%d round-trip mismatch", direction, size)
			}
			messageKey[0] ^= 1
			if _, err := box.Open(make([]byte, 0, size), messageKey[:], ciphertext, direction); !errors.Is(err, ErrMTProtoMessageKey) {
				t.Fatalf("direction=%d size=%d error=%v", direction, size, err)
			}
		}
	}
}

func TestMTProtoSealBatch(t *testing.T) {
	streams := make([]MTProtoSealStream, 8)
	for i := range streams {
		box, err := NewMTProto(makePattern(256, byte(i+10)))
		if err != nil {
			t.Fatal(err)
		}
		plain := makePattern(4096, byte(i+30))
		streams[i] = MTProtoSealStream{Box: box, Dst: make([]byte, 0, len(plain)), Plaintext: plain, Direction: Direction(i & 1)}
	}
	if err := (&MTProto{}).SealBatch(streams); err != nil {
		t.Fatal(err)
	}
	opens := make([]MTProtoOpenStream, len(streams))
	for i := range streams {
		opens[i] = MTProtoOpenStream{Box: streams[i].Box, Dst: make([]byte, 0, len(streams[i].Plaintext)), Ciphertext: streams[i].Ciphertext, MessageKey: streams[i].MessageKey[:], Direction: streams[i].Direction}
	}
	if err := (&MTProto{}).OpenBatch(opens); err != nil {
		t.Fatal(err)
	}
	for i := range opens {
		if !bytes.Equal(opens[i].Plaintext, streams[i].Plaintext) {
			t.Fatalf("stream=%d mismatch", i)
		}
	}
}

func TestMTProtoAllocs(t *testing.T) {
	box, err := NewMTProto(makePattern(256, 3))
	if err != nil {
		t.Fatal(err)
	}
	plain := makePattern(4096, 5)
	out := make([]byte, 0, len(plain))
	if allocs := testing.AllocsPerRun(1000, func() {
		if _, _, err := box.Seal(out[:0], plain, ClientToServer); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("Seal allocs/op = %v, want 0", allocs)
	}
}

func TestMTProtoDerivationReference(t *testing.T) {
	auth := makePattern(256, 97)
	box, err := NewMTProto(auth)
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []Direction{ClientToServer, ServerToClient} {
		for _, size := range []int{0, 16, 64, 65, 4096, 65537} {
			plain := makePattern(size, byte(size+11))
			var messageKey [16]byte
			box.messageKey(&messageKey, plain, direction)
			wantMessageKey, err := MessageKey(auth, plain, direction)
			if err != nil {
				t.Fatal(err)
			}
			if messageKey != wantMessageKey {
				t.Fatalf("message key direction=%d size=%d", direction, size)
			}
			box.derive(&messageKey, direction)
			wantKey, wantIV, err := DeriveMessageAES(auth, messageKey[:], direction)
			if err != nil {
				t.Fatal(err)
			}
			if box.key != wantKey || box.iv != wantIV {
				t.Fatalf("AES derivation direction=%d size=%d", direction, size)
			}
			clear(box.key[:])
			clear(box.iv[:])
		}
	}
}

func TestMTProtoBatchAllocs(t *testing.T) {
	streams := make([]MTProtoSealStream, 4)
	for i := range streams {
		box, err := NewMTProto(makePattern(256, byte(i+70)))
		if err != nil {
			t.Fatal(err)
		}
		streams[i] = MTProtoSealStream{Box: box, Dst: make([]byte, 0, 4096), Plaintext: makePattern(4096, byte(i+80)), Direction: ClientToServer}
	}
	if allocs := testing.AllocsPerRun(1000, func() {
		if err := (&MTProto{}).SealBatch(streams); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("batch allocs/op = %v, want 0", allocs)
	}
}

func TestGCMAllocs(t *testing.T) {
	gcm, err := NewGCM(makePattern(32, 1))
	if err != nil {
		t.Fatal(err)
	}
	nonce := makePattern(12, 2)
	plain := makePattern(65536, 3)
	sealed := make([]byte, 0, len(plain)+16)
	if allocs := testing.AllocsPerRun(1000, func() {
		if _, err := gcm.Seal(sealed[:0], nonce, plain, nil); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("Seal allocs/op=%v, want 0", allocs)
	}
	ciphertext, err := gcm.Seal(sealed[:0], nonce, plain, nil)
	if err != nil {
		t.Fatal(err)
	}
	opened := make([]byte, 0, len(plain))
	if allocs := testing.AllocsPerRun(1000, func() {
		if _, err := gcm.Open(opened[:0], nonce, ciphertext, nil); err != nil {
			t.Fatal(err)
		}
	}); allocs != 0 {
		t.Fatalf("Open allocs/op=%v, want 0", allocs)
	}
}

func TestLocalKeyNIExperiment(t *testing.T) {
	for _, password := range [][]byte{nil, []byte("password"), makePattern(79, 7)} {
		for _, salt := range [][]byte{nil, []byte("salt"), makePattern(97, 11)} {
			for _, iterations := range []int{1, 2, 3, 17, 257} {
				got, err := deriveLocalKeyNIExperiment(password, salt, iterations)
				if err != nil {
					t.Fatal(err)
				}
				want, err := pbkdf2.Key(sha256.New, string(password), salt, iterations, 32)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got[:], want) {
					t.Fatalf("iterations=%d password=%d salt=%d got=%x want=%x", iterations, len(password), len(salt), got, want)
				}
			}
		}
	}
}

func TestLocalKeyNIExperimentRandom(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261119, 609221))
	for i := 0; i < 64; i++ {
		password := make([]byte, rng.IntN(161))
		salt := make([]byte, rng.IntN(193))
		for j := range password {
			password[j] = byte(rng.Uint64())
		}
		for j := range salt {
			salt[j] = byte(rng.Uint64())
		}
		iterations := 1 + rng.IntN(1024)
		got, err := deriveLocalKeyNIExperiment(password, salt, iterations)
		if err != nil {
			t.Fatal(err)
		}
		want, err := pbkdf2.Key(sha256.New, string(password), salt, iterations, 32)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[:], want) {
			t.Fatalf("random vector %d iterations=%d got=%x want=%x", i, iterations, got, want)
		}
	}
}

func TestSHA256NIExperimentDispatch(t *testing.T) {
	if nativeSHA256Block != nil && nativePBKDF2Iterations == nil {
		t.Fatal("SHA-NI block core without iteration core")
	}
}
func TestLocalKeyNIExperimentVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/local_key_vectors.csv")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows[1:] {
		password, err := hex.DecodeString(row[1])
		if err != nil {
			t.Fatal(err)
		}
		salt, err := hex.DecodeString(row[2])
		if err != nil {
			t.Fatal(err)
		}
		iterations, err := strconv.Atoi(row[3])
		if err != nil {
			t.Fatal(err)
		}
		want, err := hex.DecodeString(row[4])
		if err != nil {
			t.Fatal(err)
		}
		got, err := deriveLocalKeyNIExperiment(password, salt, iterations)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[:], want) {
			t.Fatalf("vector %s got=%x want=%x", row[0], got, want)
		}
	}
}
