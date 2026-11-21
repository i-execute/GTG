package core

func init() {
	if hasSHA256NI() {
		nativeSHA256Block = sha256BlockNI
		nativePBKDF2Iterations = pbkdf2NIIterations
	}
}

func hasSHA256NI() bool
func sha256BlockNI(state *[8]uint32, block *[64]byte)

func pbkdf2NIIterations(state, inner, outer *[8]uint32, u, out *[32]byte, iterations int)
