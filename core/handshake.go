package core

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"math/bits"
	"sync"
)

var ErrHandshake = errors.New("gtg: handshake input rejected")

type RSAPublicKey struct {
	Modulus  []byte
	Exponent []byte
}

type TemporaryAES struct {
	Key [32]byte
	IV  [32]byte
}

var safePrimeCache sync.Map

func FactorPQ(pq uint64) (uint64, uint64, error) {
	if pq < 15 || pq&1 == 0 {
		return 0, 0, ErrHandshake
	}
	for _, divisor := range [...]uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97} {
		if pq%divisor == 0 {
			other := pq / divisor
			if divisor == other || !isPrime64(other) {
				return 0, 0, ErrHandshake
			}
			return divisor, other, nil
		}
	}
	if isPrime64(pq) {
		return 0, 0, ErrHandshake
	}
	for _, seed := range [...]uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37} {
		factor := brentFactor(pq, seed)
		if factor > 1 && factor < pq {
			other := pq / factor
			if factor != other && isPrime64(factor) && isPrime64(other) {
				if factor > other {
					factor, other = other, factor
				}
				return factor, other, nil
			}
		}
	}
	return 0, 0, ErrHandshake
}

func FactorPQBytes(pq []byte) ([]byte, []byte, error) {
	if len(pq) == 0 || len(pq) > 8 {
		return nil, nil, ErrHandshake
	}
	var value uint64
	for _, b := range pq {
		value = value<<8 | uint64(b)
	}
	p, q, err := FactorPQ(value)
	if err != nil {
		return nil, nil, err
	}
	return uint64Bytes(p), uint64Bytes(q), nil
}

func RSAFingerprint(key RSAPublicKey) (uint64, error) {
	if len(key.Modulus) != 256 || len(key.Exponent) == 0 || len(key.Exponent) > 8 {
		return 0, ErrHandshake
	}
	serialized := make([]byte, 0, tlBytesSize(key.Modulus)+tlBytesSize(key.Exponent))
	serialized = appendTLBytes(serialized, key.Modulus)
	serialized = appendTLBytes(serialized, key.Exponent)
	hash := sha1.Sum(serialized)
	value := binary.LittleEndian.Uint64(hash[12:])
	clear(serialized)
	clear(hash[:])
	return value, nil
}

func RSAEncryptPad(data []byte, key RSAPublicKey, source io.Reader) ([]byte, error) {
	if len(data) > 144 || len(key.Modulus) != 256 || len(key.Exponent) == 0 {
		return nil, ErrHandshake
	}
	if source == nil {
		source = rand.Reader
	}
	modulus := new(big.Int).SetBytes(key.Modulus)
	exponent := new(big.Int).SetBytes(key.Exponent)
	if modulus.BitLen() != 2048 || exponent.Sign() <= 0 {
		modulus.SetInt64(0)
		exponent.SetInt64(0)
		return nil, ErrHandshake
	}
	for attempts := 0; attempts < 128; attempts++ {
		var padded [192]byte
		copy(padded[:], data)
		if _, err := io.ReadFull(source, padded[len(data):]); err != nil {
			clear(padded[:])
			break
		}
		var temporary [32]byte
		if _, err := io.ReadFull(source, temporary[:]); err != nil {
			clear(padded[:])
			clear(temporary[:])
			break
		}
		var reversed [192]byte
		for i := range padded {
			reversed[len(padded)-1-i] = padded[i]
		}
		hash := sum256(temporary[:], padded[:])
		var input [224]byte
		copy(input[:192], reversed[:])
		copy(input[192:], hash[:])
		ige, err := NewIGE(temporary[:])
		if err != nil {
			clear(padded[:])
			clear(temporary[:])
			clear(reversed[:])
			clear(hash[:])
			clear(input[:])
			break
		}
		var encrypted [224]byte
		var zeroIV [32]byte
		if err := ige.Encrypt(encrypted[:], input[:], zeroIV[:]); err != nil {
			ige.Destroy()
			clear(padded[:])
			clear(temporary[:])
			clear(reversed[:])
			clear(hash[:])
			clear(input[:])
			clear(encrypted[:])
			break
		}
		ige.Destroy()
		mask := sha256.Sum256(encrypted[:])
		for i := range temporary {
			temporary[i] ^= mask[i]
		}
		var candidate [256]byte
		copy(candidate[:32], temporary[:])
		copy(candidate[32:], encrypted[:])
		value := new(big.Int).SetBytes(candidate[:])
		if value.Cmp(modulus) < 0 {
			result := new(big.Int).Exp(value, exponent, modulus)
			out := make([]byte, 256)
			result.FillBytes(out)
			result.SetInt64(0)
			value.SetInt64(0)
			clear(padded[:])
			clear(temporary[:])
			clear(reversed[:])
			clear(hash[:])
			clear(input[:])
			clear(encrypted[:])
			clear(mask[:])
			clear(candidate[:])
			modulus.SetInt64(0)
			exponent.SetInt64(0)
			return out, nil
		}
		value.SetInt64(0)
		clear(padded[:])
		clear(temporary[:])
		clear(reversed[:])
		clear(hash[:])
		clear(input[:])
		clear(encrypted[:])
		clear(mask[:])
		clear(candidate[:])
	}
	modulus.SetInt64(0)
	exponent.SetInt64(0)
	return nil, ErrHandshake
}

func DeriveHandshakeTemporaryAES(newNonce []byte, serverNonce []byte) (TemporaryAES, error) {
	var out TemporaryAES
	if len(newNonce) != 32 || len(serverNonce) != 16 {
		return out, ErrHandshake
	}
	a := sha1.Sum(appendBytes(newNonce, serverNonce))
	b := sha1.Sum(appendBytes(serverNonce, newNonce))
	c := sha1.Sum(appendBytes(newNonce, newNonce))
	copy(out.Key[:20], a[:])
	copy(out.Key[20:], b[:12])
	copy(out.IV[:8], b[12:])
	copy(out.IV[8:28], c[:])
	copy(out.IV[28:], newNonce[:4])
	clear(a[:])
	clear(b[:])
	clear(c[:])
	return out, nil
}

func ServerSalt(newNonce, serverNonce []byte) ([8]byte, error) {
	var out [8]byte
	if len(newNonce) != 32 || len(serverNonce) != 16 {
		return out, ErrHandshake
	}
	for i := range out {
		out[i] = newNonce[i] ^ serverNonce[i]
	}
	return out, nil
}

func EncryptDHAnswer(inner []byte, material TemporaryAES, source io.Reader) ([]byte, error) {
	if len(inner) == 0 {
		return nil, ErrHandshake
	}
	if source == nil {
		source = rand.Reader
	}
	hash := sha1.Sum(inner)
	length := len(hash) + len(inner)
	padding := (16 - length&15) & 15
	data := make([]byte, length+padding)
	copy(data, hash[:])
	copy(data[len(hash):], inner)
	if padding != 0 {
		if _, err := io.ReadFull(source, data[length:]); err != nil {
			clear(hash[:])
			clear(data)
			return nil, ErrHandshake
		}
	}
	ige, err := NewIGE(material.Key[:])
	if err != nil {
		clear(hash[:])
		clear(data)
		return nil, ErrHandshake
	}
	out := make([]byte, len(data))
	err = ige.Encrypt(out, data, material.IV[:])
	ige.Destroy()
	clear(hash[:])
	clear(data)
	if err != nil {
		clear(out)
		return nil, ErrHandshake
	}
	return out, nil
}

func DecryptDHAnswer(ciphertext []byte, material TemporaryAES, innerLength int) ([]byte, error) {
	if len(ciphertext) < 20 || len(ciphertext)&15 != 0 || innerLength <= 0 || innerLength+20 > len(ciphertext) {
		return nil, ErrHandshake
	}
	ige, err := NewIGE(material.Key[:])
	if err != nil {
		return nil, ErrHandshake
	}
	out := make([]byte, len(ciphertext))
	err = ige.Decrypt(out, ciphertext, material.IV[:])
	ige.Destroy()
	if err != nil {
		clear(out)
		return nil, ErrHandshake
	}
	hash := sha1.Sum(out[20 : 20+innerLength])
	if subtle.ConstantTimeCompare(hash[:], out[:20]) != 1 {
		clear(hash[:])
		clear(out)
		return nil, ErrHandshake
	}
	clear(hash[:])
	return out[20 : 20+innerLength], nil
}

func GenerateDHSecret(prime []byte, source io.Reader) ([]byte, error) {
	var out []byte
	if len(prime) != 256 {
		return nil, ErrHandshake
	}
	if source == nil {
		source = rand.Reader
	}
	p := new(big.Int).SetBytes(prime)
	limit := new(big.Int).Sub(p, big.NewInt(3))
	secret, err := rand.Int(source, limit)
	if err == nil {
		secret.Add(secret, big.NewInt(2))
		out = make([]byte, 256)
		secret.FillBytes(out)
		secret.SetInt64(0)
	}
	p.SetInt64(0)
	limit.SetInt64(0)
	if err != nil {
		return nil, ErrHandshake
	}
	return out, nil
}

func ComputeDHAuthKey(prime, peer, secret []byte) ([]byte, error) {
	if len(prime) != 256 || len(peer) != 256 || len(secret) == 0 {
		return nil, ErrHandshake
	}
	if err := ValidateDHPublic(prime, peer); err != nil {
		return nil, ErrHandshake
	}
	p := new(big.Int).SetBytes(prime)
	g := new(big.Int).SetBytes(peer)
	a := new(big.Int).SetBytes(secret)
	if a.Sign() <= 0 {
		p.SetInt64(0)
		g.SetInt64(0)
		a.SetInt64(0)
		return nil, ErrHandshake
	}
	result := new(big.Int).Exp(g, a, p)
	out := make([]byte, 256)
	result.FillBytes(out)
	p.SetInt64(0)
	g.SetInt64(0)
	a.SetInt64(0)
	result.SetInt64(0)
	return out, nil
}

func ValidateTelegramDH(prime []byte, generator int) error {
	digest := sha256.Sum256(prime)
	if _, ok := safePrimeCache.Load(digest); !ok {
		if err := ValidateSafePrime(prime, generator); err != nil {
			return ErrHandshake
		}
		safePrimeCache.Store(digest, struct{}{})
		clear(digest[:])
		return nil
	}
	p := new(big.Int).SetBytes(prime)
	valid := validGeneratorResidue(p, generator)
	p.SetInt64(0)
	clear(digest[:])
	if !valid {
		return ErrHandshake
	}
	return nil
}

func isPrime64(n uint64) bool {
	if n < 2 {
		return false
	}
	for _, small := range [...]uint64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37} {
		if n == small {
			return true
		}
		if n%small == 0 {
			return false
		}
	}
	d := n - 1
	s := 0
	for d&1 == 0 {
		d >>= 1
		s++
	}
	for _, a := range [...]uint64{2, 325, 9375, 28178, 450775, 9780504, 1795265022} {
		if a%n == 0 {
			continue
		}
		x := powMod64(a%n, d, n)
		if x == 1 || x == n-1 {
			continue
		}
		passed := false
		for r := 1; r < s; r++ {
			x = mulMod64(x, x, n)
			if x == n-1 {
				passed = true
				break
			}
		}
		if !passed {
			return false
		}
	}
	return true
}

func brentFactor(n, seed uint64) uint64 {
	if n&1 == 0 {
		return 2
	}
	y := seed%(n-1) + 1
	c := (seed*seed+1)%(n-1) + 1
	m := uint64(128)
	g, r, q := uint64(1), uint64(1), uint64(1)
	var x, ys uint64
	for g == 1 && r < 1<<24 {
		x = y
		for i := uint64(0); i < r; i++ {
			y = addMod64Handshake(mulMod64(y, y, n), c, n)
		}
		k := uint64(0)
		for k < r && g == 1 {
			ys = y
			limit := m
			if r-k < limit {
				limit = r - k
			}
			q = 1
			for i := uint64(0); i < limit; i++ {
				y = addMod64Handshake(mulMod64(y, y, n), c, n)
				q = mulMod64(q, difference64(x, y), n)
			}
			g = gcd64(q, n)
			k += limit
		}
		r <<= 1
	}
	if g == n {
		for g == 1 {
			ys = addMod64Handshake(mulMod64(ys, ys, n), c, n)
			g = gcd64(difference64(x, ys), n)
		}
	}
	if g == n {
		return 0
	}
	return g
}

func addMod64Handshake(a, b, modulus uint64) uint64 {
	sum := a + b
	if sum < a || sum >= modulus {
		return sum - modulus
	}
	return sum
}

func mulMod64(a, b, modulus uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, remainder := bits.Div64(hi, lo, modulus)
	return remainder
}

func powMod64(a, exponent, modulus uint64) uint64 {
	out := uint64(1)
	for exponent != 0 {
		if exponent&1 != 0 {
			out = mulMod64(out, a, modulus)
		}
		a = mulMod64(a, a, modulus)
		exponent >>= 1
	}
	return out
}

func difference64(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return b - a
}

func gcd64(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func uint64Bytes(value uint64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	first := 0
	for first < len(raw)-1 && raw[first] == 0 {
		first++
	}
	return append([]byte(nil), raw[first:]...)
}

func appendBytes(parts ...[]byte) []byte {
	length := 0
	for _, part := range parts {
		length += len(part)
	}
	out := make([]byte, 0, length)
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func tlBytesSize(data []byte) int {
	if len(data) < 254 {
		return (len(data) + 1 + 3) &^ 3
	}
	return (len(data) + 4 + 3) &^ 3
}

func appendTLBytes(dst, data []byte) []byte {
	if len(data) < 254 {
		dst = append(dst, byte(len(data)))
	} else {
		dst = append(dst, 254, byte(len(data)), byte(len(data)>>8), byte(len(data)>>16))
	}
	dst = append(dst, data...)
	for len(dst)&3 != 0 {
		dst = append(dst, 0)
	}
	return dst
}
