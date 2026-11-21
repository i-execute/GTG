package vault

import "testing"

func BenchmarkKDF(b *testing.B) {
	passphrase := []byte("benchmark password")
	salt := pattern(16, 71)
	for _, parameters := range []KDFParameters{DefaultArgon2id(), DefaultPBKDF2()} {
		b.Run(kdfName(parameters), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				key, err := derivePassphrase(passphrase, salt, parameters)
				if err != nil {
					b.Fatal(err)
				}
				clear(key[:])
			}
		})
	}
}

func BenchmarkVaultRawRoundTrip(b *testing.B) {
	credential, err := NewRawCredential(pattern(32, 72))
	if err != nil {
		b.Fatal(err)
	}
	vault := New()
	if err := vault.Put("session", pattern(4096, 73)); err != nil {
		b.Fatal(err)
	}
	defer vault.Destroy()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		encoded, err := vault.Marshal(credential)
		if err != nil {
			b.Fatal(err)
		}
		opened, err := Open(encoded, credential)
		clear(encoded)
		if err != nil {
			b.Fatal(err)
		}
		opened.Destroy()
	}
}

func kdfName(parameters KDFParameters) string {
	if parameters.Algorithm == Argon2id {
		return "Argon2id"
	}
	return "PBKDF2SHA256"
}
