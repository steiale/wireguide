package ipc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Max message size: 1MB (prevents memory exhaustion from malformed frames).
const maxFrameSize = 1024 * 1024

// WriteFrame writes a length-prefixed JSON-serialized message to w.
func WriteFrame(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return writeRawFrame(w, data)
}

// writeRawFrame writes an already-encoded message. Header and body go out in
// one Write so concurrent writers can't interleave them.
func writeRawFrame(w io.Writer, data []byte) error {
	if len(data) > maxFrameSize {
		return fmt.Errorf("frame too large: %d bytes", len(data))
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// ReadFrame reads a length-prefixed message from r into v.
func ReadFrame(r io.Reader, v interface{}) error {
	body, err := ReadFrameRaw(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// ReadFrameRaw reads a length-prefixed message and returns the raw bytes.
func ReadFrameRaw(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > maxFrameSize {
		return nil, fmt.Errorf("frame too large: %d bytes", length)
	}
	if length == 0 {
		return nil, fmt.Errorf("empty frame")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}
