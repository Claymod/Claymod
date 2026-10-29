package proto

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
)

// FuzzReadFrame: the codec must never panic and never allocate a buffer
// beyond MaxFrameSize regardless of attacker-chosen input; every input
// yields a valid frame or an error.
func FuzzReadFrame(f *testing.F) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 0)
	f.Add(hdr[:])                                    // empty frame
	f.Add([]byte{0, 0, 0, 1, 'x'})                   // 1-byte payload
	binary.BigEndian.PutUint32(hdr[:], MaxFrameSize) // exact cap
	f.Add(hdr[:])                                    // cap header, no payload
	binary.BigEndian.PutUint32(hdr[:], MaxFrameSize+1)
	f.Add(hdr[:]) // oversized header
	binary.BigEndian.PutUint32(hdr[:], 0xFFFFFFFF)
	f.Add(hdr[:])                       // huge header
	f.Add([]byte{0, 0, 0, 8, 'a', 'b'}) // truncated payload
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &sliceReader{data: data}
		payload, err := readFrame(r)
		if err != nil {
			return // error is a valid outcome
		}
		if len(payload) > MaxFrameSize {
			t.Fatalf("readFrame returned %d bytes > MaxFrameSize", len(payload))
		}
	})
}

// sliceReader adapts a byte slice to io.Reader for the fuzz driver.
type sliceReader struct{ data []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// FuzzHandshakeDecode: a hostile handshake payload must never panic;
// decode either yields a struct or an error.
func FuzzHandshakeDecode(f *testing.F) {
	f.Add([]byte(`{"role":"agent","version":1}`))
	f.Add([]byte(`{"role":"control","version":999}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"role":123,"version":"one"}`))
	f.Add([]byte(`{"role":"agent","version":1,"extra":`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var hs Handshake
		// Must not panic; error or valid decode are both fine.
		_ = json.Unmarshal(data, &hs)
	})
}
