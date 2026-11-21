package core

var matrixSizes = []int{64, 256, 1024, 4096, 16384, 65536, 524288, 1048576, 16777216}

func sizeName(size int) string {
	switch size {
	case 64:
		return "64B"
	case 256:
		return "256B"
	case 1024:
		return "1KiB"
	case 4096:
		return "4KiB"
	case 16384:
		return "16KiB"
	case 65536:
		return "64KiB"
	case 524288:
		return "512KiB"
	case 1048576:
		return "1MiB"
	case 16777216:
		return "16MiB"
	default:
		return "unknown"
	}
}

func matrixSizeName(size int) string {
	return sizeName(size)
}
