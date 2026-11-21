package client

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestRPCErrorClassification(t *testing.T) {
	for _, item := range []struct {
		message string
		wait    int
		dc      int
	}{
		{message: "FLOOD_WAIT_12", wait: 12},
		{message: "USER_MIGRATE_4", dc: 4},
		{message: "SOMETHING", wait: 0, dc: 0},
	} {
		err, ok := parseRPCError(420, item.message).(*RPCError)
		if !ok || err.FloodWait != item.wait || err.MigrateDC != item.dc {
			t.Fatal(item.message)
		}
	}
}

func TestTLBytesAndGzipLimitPath(t *testing.T) {
	data, err := tlBytes([]byte{3, 'a', 'b', 'c'})
	if err != nil || !bytes.Equal(data, []byte("abc")) {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := unpackGzip(buffer.Bytes())
	if err != nil || !bytes.Equal(opened, []byte("payload")) {
		t.Fatal(err)
	}
}
