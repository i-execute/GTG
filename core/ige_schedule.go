package core

func expand256Schedule(key *[32]byte, enc, dec *[240]byte) {
	copy(enc[:32], key[:])
	rcon := byte(1)
	for offset := 32; offset < len(enc); offset += 4 {
		a, b, c, d := enc[offset-4], enc[offset-3], enc[offset-2], enc[offset-1]
		switch offset & 31 {
		case 0:
			a, b, c, d = aesSBox(b), aesSBox(c), aesSBox(d), aesSBox(a)
			a ^= rcon
			rcon = aesXTime(rcon)
		case 16:
			a, b, c, d = aesSBox(a), aesSBox(b), aesSBox(c), aesSBox(d)
		}
		enc[offset] = enc[offset-32] ^ a
		enc[offset+1] = enc[offset-31] ^ b
		enc[offset+2] = enc[offset-30] ^ c
		enc[offset+3] = enc[offset-29] ^ d
	}
	for round := 0; round < 15; round++ {
		copy(dec[round*16:(round+1)*16], enc[(14-round)*16:(15-round)*16])
	}
}

func aesSBox(value byte) byte {
	inverse := aesPower(value, 254)
	return inverse ^ rotByte(inverse, 1) ^ rotByte(inverse, 2) ^ rotByte(inverse, 3) ^ rotByte(inverse, 4) ^ 0x63
}

func aesPower(value byte, exponent byte) byte {
	out := byte(1)
	for bit := 7; bit >= 0; bit-- {
		out = aesMultiply(out, out)
		if exponent&(1<<uint(bit)) != 0 {
			out = aesMultiply(out, value)
		}
	}
	return out
}

func aesMultiply(a, b byte) byte {
	out := byte(0)
	for range 8 {
		mask := byte(0) - (b & 1)
		out ^= a & mask
		top := a >> 7
		a = (a << 1) ^ (0x1b & (byte(0) - top))
		b >>= 1
	}
	return out
}

func aesXTime(value byte) byte {
	return (value << 1) ^ (0x1b & (byte(0) - (value >> 7)))
}

func rotByte(value byte, count uint) byte {
	return value<<count | value>>(8-count)
}
