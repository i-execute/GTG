package core

func init() {
	if hasAESARM() {
		nativeIGEPrepare = expand256ARM
		nativeIGEEncrypt = encryptIGEARM
		nativeIGEDecrypt = decryptIGEARM
	}
}

func hasAESARM() bool
func encryptIGEARM(dst, src []byte, enc *[240]byte, iv *[32]byte)
func decryptIGEARM(dst, src []byte, dec *[240]byte, iv *[32]byte)
func prepareDecryptARM(enc, dec *[240]byte)

func expand256ARM(key *[32]byte, enc, dec *[240]byte) {
	expand256Schedule(key, enc, dec)
	prepareDecryptARM(enc, dec)
}
