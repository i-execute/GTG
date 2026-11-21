package core

func init() {
	if hasAESNI() {
		nativeIGEPrepare = expand256AESNI
		nativeIGEEncrypt = encryptIGEFoldAESNI
		nativeIGEDecrypt = decryptIGEAESNI
		nativeIGEEncrypt4 = encryptIGE4AESNI
		nativeIGEReferenceEncrypt = referenceIGEEncryptAESNI
		nativeIGEReferenceDecrypt = referenceIGEDecryptAESNI
		nativeIGEEncrypt4Varied = encryptIGE4VariedAESNI
		nativeIGEDecrypt4Varied = decryptIGE4VariedAESNI
	}
}

func hasAESNI() bool
func expand256AESNI(key *[32]byte, enc, dec *[240]byte)
func encryptIGEAESNI(dst, src []byte, enc *[240]byte, iv *[32]byte)
func encryptIGEFoldAESNI(dst, src []byte, enc *[240]byte, iv *[32]byte)
func decryptIGEAESNI(dst, src []byte, dec *[240]byte, iv *[32]byte)
func referenceIGEEncryptAESNI(dst, src []byte, enc *[240]byte)
func referenceIGEDecryptAESNI(dst, src []byte, dec *[240]byte)
func encryptIGE4VariedAESNI(streams *IGEKeyStream, blocks uintptr)
func decryptIGE4VariedAESNI(streams *IGEKeyStream, blocks uintptr)
func encryptIGE4AESNI(streams *IGEStream, enc *[240]byte, blocks uintptr)
