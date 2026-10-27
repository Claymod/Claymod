package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payloads := [][]byte{
		[]byte("hello"),
		{},
		bytes.Repeat([]byte("x"), 1000),
	}
	for _, want := range payloads {
		var buf bytes.Buffer
		if err := writeFrame(&buf, want); err != nil {
			t.Fatalf("writeFrame returned error: %v", err)
		}
		got, err := readFrame(&buf)
		if err != nil {
			t.Fatalf("readFrame returned error: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("round trip mismatch: got %d bytes, want %d", len(got), len(want))
		}
	}
}

func TestFrameMultipleSequential(t *testing.T) {
	var buf bytes.Buffer
	for k := 0; k < 5; k++ {
		if err := writeFrame(&buf, []byte{byte(k)}); err != nil {
			t.Fatal(err)
		}
	}
	for k := 0; k < 5; k++ {
		got, err := readFrame(&buf)
		if err != nil {
			t.Fatalf("readFrame %d: %v", k, err)
		}
		if len(got) != 1 || got[0] != byte(k) {
			t.Errorf("frame %d = %v, want [%d]", k, got, k)
		}
	}
	if _, err := readFrame(&buf); !errors.Is(err, io.EOF) {
		t.Errorf("after drain readFrame error = %v, want io.EOF", err)
	}
}

func TestReadFrameRejectsOversizedHeader(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(MaxFrameSize)+1)
	buf.Write(hdr[:])
	buf.Write(bytes.Repeat([]byte("x"), 64)) // attacker-supplied tail
	_, err := readFrame(&buf)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("readFrame error = %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFrameRejectsHugeHeader(t *testing.T) {
	// A header claiming 4 GiB must be rejected without allocating.
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], ^uint32(0))
	buf.Write(hdr[:])
	_, err := readFrame(&buf)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("readFrame error = %v, want ErrFrameTooLarge", err)
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	big := make([]byte, MaxFrameSize+1)
	if err := writeFrame(io.Discard, big); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("writeFrame error = %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFrameTruncatedHeader(t *testing.T) {
	// Only 2 of 4 header bytes.
	_, err := readFrame(bytes.NewReader([]byte{0, 1}))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("readFrame error = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadFrameTruncatedPayload(t *testing.T) {
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 10)
	buf.Write(hdr[:])
	buf.WriteString("short") // claims 10, sends 5
	_, err := readFrame(&buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("readFrame error = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadFrameEmptyStream(t *testing.T) {
	_, err := readFrame(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("readFrame error = %v, want io.EOF", err)
	}
}
