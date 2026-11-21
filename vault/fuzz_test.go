package vault

import "testing"

func FuzzOpen(f *testing.F) {
	credential, err := NewRawCredential(pattern(32, 61))
	if err != nil {
		f.Fatal(err)
	}
	vault := New()
	if err := vault.Put("seed", pattern(16, 62)); err != nil {
		f.Fatal(err)
	}
	encoded, err := vault.Marshal(credential)
	vault.Destroy()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte("bad"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		opened, err := Open(data, credential)
		if err == nil {
			opened.Destroy()
		}
	})
}

func FuzzDecodePortable(f *testing.F) {
	f.Add("gtgv1:AA")
	f.Add("invalid")
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 1<<20 {
			t.Skip()
		}
		decoded, err := DecodePortable(value)
		if err == nil {
			clear(decoded)
		}
	})
}
