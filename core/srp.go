package core

import (
	"crypto/sha256"
	"errors"
	"math/big"
)

var ErrSRPParameters = errors.New("gtg: invalid SRP parameters")
var ErrSRPSecret = errors.New("gtg: invalid SRP secret")

type SRPParameters struct {
	ID        int64
	Generator int
	Prime     []byte
	Salt1     []byte
	Salt2     []byte
	PublicB   []byte
}

type SRPProof struct {
	ID int64
	A  []byte
	M1 [32]byte
}

func BuildSRPProof(parameters SRPParameters, password string, privateA []byte) (SRPProof, error) {
	var proof SRPProof
	width := len(parameters.Prime)
	if width == 0 || len(parameters.PublicB) != width || parameters.Generator < 2 || parameters.Generator > 7 {
		return proof, ErrSRPParameters
	}
	p := new(big.Int).SetBytes(parameters.Prime)
	b := new(big.Int).SetBytes(parameters.PublicB)
	a := new(big.Int).SetBytes(privateA)
	if p.Sign() <= 0 || b.Sign() <= 0 || b.Cmp(p) >= 0 || a.Sign() <= 0 {
		return proof, ErrSRPSecret
	}
	g := big.NewInt(int64(parameters.Generator))
	gBytes := paddedInt(g, width)
	xHash, err := TelegramPasswordHash(password, parameters.Salt1, parameters.Salt2)
	if err != nil {
		return proof, err
	}
	x := new(big.Int).SetBytes(xHash[:])
	v := new(big.Int).Exp(g, x, p)
	kHash := sum256(parameters.Prime, gBytes)
	k := new(big.Int).SetBytes(kHash[:])
	kgx := new(big.Int).Mul(k, v)
	kgx.Mod(kgx, p)
	publicAInt := new(big.Int).Exp(g, a, p)
	publicA := paddedInt(publicAInt, width)
	uHash := sum256(publicA, parameters.PublicB)
	u := new(big.Int).SetBytes(uHash[:])
	if u.Sign() == 0 {
		return proof, ErrSRPSecret
	}
	t := new(big.Int).Sub(b, kgx)
	t.Mod(t, p)
	exponent := new(big.Int).Mul(u, x)
	exponent.Add(exponent, a)
	shared := new(big.Int).Exp(t, exponent, p)
	sharedBytes := paddedInt(shared, width)
	key := sha256.Sum256(sharedBytes)
	primeHash := sha256.Sum256(parameters.Prime)
	gHash := sha256.Sum256(gBytes)
	var xor [32]byte
	for i := range xor {
		xor[i] = primeHash[i] ^ gHash[i]
	}
	salt1Hash := sha256Bytes(parameters.Salt1)
	salt2Hash := sha256Bytes(parameters.Salt2)
	proof.ID = parameters.ID
	proof.A = publicA
	proof.M1 = sum256(xor[:], salt1Hash[:], salt2Hash[:], publicA, parameters.PublicB, key[:])
	clear(gBytes)
	clear(xHash[:])
	clear(kHash[:])
	clear(uHash[:])
	clear(sharedBytes)
	clear(primeHash[:])
	clear(gHash[:])
	clear(salt1Hash[:])
	clear(salt2Hash[:])
	clear(xor[:])
	clear(key[:])
	p.SetInt64(0)
	b.SetInt64(0)
	a.SetInt64(0)
	x.SetInt64(0)
	v.SetInt64(0)
	k.SetInt64(0)
	kgx.SetInt64(0)
	publicAInt.SetInt64(0)
	u.SetInt64(0)
	t.SetInt64(0)
	exponent.SetInt64(0)
	shared.SetInt64(0)
	return proof, nil
}

func ValidateSafePrime(prime []byte, generator int) error {
	if len(prime) != 256 || generator < 2 || generator > 7 {
		return ErrSRPParameters
	}
	p := new(big.Int).SetBytes(prime)
	if p.BitLen() != 2048 || !p.ProbablyPrime(64) {
		return ErrSRPParameters
	}
	q := new(big.Int).Sub(p, big.NewInt(1))
	q.Rsh(q, 1)
	if !q.ProbablyPrime(64) || !validGeneratorResidue(p, generator) {
		return ErrSRPParameters
	}
	p.SetInt64(0)
	q.SetInt64(0)
	return nil
}

func ValidateDHPublic(prime, public []byte) error {
	if len(prime) != 256 || len(public) != 256 {
		return ErrSRPParameters
	}
	p := new(big.Int).SetBytes(prime)
	v := new(big.Int).SetBytes(public)
	limit := new(big.Int).Lsh(big.NewInt(1), 1984)
	upper := new(big.Int).Sub(p, limit)
	valid := v.Cmp(limit) > 0 && v.Cmp(upper) < 0
	p.SetInt64(0)
	v.SetInt64(0)
	limit.SetInt64(0)
	upper.SetInt64(0)
	if !valid {
		return ErrSRPParameters
	}
	return nil
}

func ModExp(base, exponent, modulus []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(modulus)
	e := new(big.Int).SetBytes(exponent)
	b := new(big.Int).SetBytes(base)
	if m.Sign() <= 0 || e.Sign() < 0 || b.Sign() < 0 {
		return nil, ErrSRPParameters
	}
	out := new(big.Int).Exp(b, e, m).Bytes()
	m.SetInt64(0)
	e.SetInt64(0)
	b.SetInt64(0)
	return out, nil
}

func paddedInt(value *big.Int, width int) []byte {
	out := make([]byte, width)
	value.FillBytes(out)
	return out
}

func validGeneratorResidue(prime *big.Int, generator int) bool {
	m := new(big.Int)
	switch generator {
	case 2:
		m.Mod(prime, big.NewInt(8))
		return m.Int64() == 7
	case 3:
		m.Mod(prime, big.NewInt(3))
		return m.Int64() == 2
	case 4:
		return true
	case 5:
		m.Mod(prime, big.NewInt(5))
		return m.Int64() == 1 || m.Int64() == 4
	case 6:
		m.Mod(prime, big.NewInt(24))
		return m.Int64() == 19 || m.Int64() == 23
	case 7:
		m.Mod(prime, big.NewInt(7))
		return m.Int64() == 3 || m.Int64() == 5 || m.Int64() == 6
	default:
		return false
	}
}

func sha256Bytes(data []byte) [32]byte {
	return sha256.Sum256(data)
}
