package core

import "hash/crc32"

var crc32CastagnoliTable = crc32.MakeTable(crc32.Castagnoli)

func CRC32IEEE(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

func CRC32Castagnoli(data []byte) uint32 {
	return crc32.Checksum(data, crc32CastagnoliTable)
}
