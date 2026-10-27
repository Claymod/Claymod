// Package proto implements the claymod wire protocol: a framed JSON
// protocol over mutual TLS TCP. Frame layout:
//
//	frame := uint32_be length || JSON payload (≤ 8 MiB)
//
// The first frame on every connection is a version handshake. All further
// frames are Request or Response messages.
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// Version is the protocol version spoken by this build. It travels as
	// a single byte field in the handshake frame.
	Version uint8 = 1

	// MaxFrameSize bounds one frame payload (8 MiB).
	MaxFrameSize = 8 << 20
)

// ErrFrameTooLarge is returned when a frame header claims more than
// MaxFrameSize bytes. It is checked before any allocation.
var ErrFrameTooLarge = errors.New("proto: frame exceeds max size")

// writeFrame writes one length-prefixed frame to w.
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(payload), MaxFrameSize)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if len(payload) == 0 {
		return nil
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	return nil
}

// readFrame reads one length-prefixed frame from r. A clean close at a
// frame boundary surfaces as io.EOF; a close mid-frame surfaces as
// io.ErrUnexpectedEOF. Oversized frames are rejected before allocation.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, n, MaxFrameSize)
	}
	if n == 0 {
		return []byte{}, nil
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
