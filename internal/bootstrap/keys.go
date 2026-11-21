package bootstrap

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"

	"github.com/i-execute/GTG/core"
)

var ErrKey = errors.New("gtg: bootstrap RSA key rejected")

const testRSAPEM = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR\nyy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv\nplUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/\nj25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1\naHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO\nj4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB\n-----END RSA PUBLIC KEY-----\n"

const mainRSAPEM = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\nt6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n-----END RSA PUBLIC KEY-----\n"

func KnownServerKeys(test bool) ([]core.RSAPublicKey, error) {
	value := mainRSAPEM
	if test {
		value = testRSAPEM
	}
	key, err := parseRSAPublicKey([]byte(value))
	if err != nil {
		return nil, err
	}
	return []core.RSAPublicKey{key}, nil
}

func parseRSAPublicKey(encoded []byte) (core.RSAPublicKey, error) {
	var out core.RSAPublicKey
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "RSA PUBLIC KEY" {
		return out, ErrKey
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil || key.N == nil || key.N.BitLen() != 2048 || key.E <= 1 {
		return out, ErrKey
	}
	out.Modulus = key.N.FillBytes(make([]byte, 256))
	out.Exponent = big.NewInt(int64(key.E)).Bytes()
	if len(out.Exponent) == 0 {
		clear(out.Modulus)
		return core.RSAPublicKey{}, ErrKey
	}
	return out, nil
}
