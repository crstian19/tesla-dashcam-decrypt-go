// Package container implements the encrypted container format Tesla introduced
// for dashcam and Sentry Mode recordings in firmware 2026.20.
//
// A recording is two 4096-byte header pages followed by the payload:
//
//	0x0000   8   plaintext MP4 size (uint64, big-endian)
//	0x0004  16   correlation id, sent as the API item id
//	0x0014   4   metadata offset, always 0x1000
//	0x1000   4   key_id (uint32, big-endian)
//	0x1004  65   public_key (uncompressed EC point, leading 0x04)
//	0x1045  17   VIN (ASCII)
//	0x1056   8   timestamp (uint64, big-endian)
//	0x105e  44   wrapped_key
//	0x2000+      AES-128-CBC payload in 4096-byte eCryptfs-style pages
//
// The id overlaps the last four bytes of the plaintext size field, so it begins
// with the low half of that size followed by constant magic and version words.
// It is not a UUID and it is not unique: two clips of exactly the same size
// share one. It only correlates a key request with its response, so callers
// must never put two colliding clips in the same request.
//
// The payload key is not derivable from the file: it is fetched from Tesla's
// API using the ownership metadata above. See package tesla.
package container

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	// PageSize is the size of one encrypted payload page.
	PageSize = 4096

	// payloadOffset is where the encrypted payload starts.
	payloadOffset = 0x2000

	// metadataOffset is the second header page, holding ownership metadata.
	metadataOffset = 0x1000

	idOffset = 4
	idSize   = 16

	// metadataOffsetField holds the offset of the metadata page, and is what
	// identifies the file as one of Tesla's containers.
	metadataOffsetField = 0x14

	keyIDOffset      = metadataOffset
	keyIDSize        = 4
	publicKeyOffset  = keyIDOffset + keyIDSize
	publicKeySize    = 65
	vinOffset        = publicKeyOffset + publicKeySize
	vinSize          = 17
	timestampOffset  = vinOffset + vinSize
	timestampSize    = 8
	wrappedKeyOffset = timestampOffset + timestampSize
	wrappedKeySize   = 44

	metadataEnd = wrappedKeyOffset + wrappedKeySize

	// probeSize is how much of the first header page identifies the container.
	probeSize = metadataOffset + keyIDSize
)

var (
	// ErrNotEncrypted means the file is not one of Tesla's encrypted containers
	// — most likely an ordinary MP4 that was already decrypted.
	ErrNotEncrypted = errors.New("not an encrypted Tesla clip")
	// ErrTooShort means the file is truncated: it cannot hold the header it needs.
	ErrTooShort = errors.New("encrypted clip is truncated")
	// ErrInvalidVIN means the VIN field is not 17 ASCII characters.
	ErrInvalidVIN = errors.New("invalid VIN in encrypted header")
	// ErrInvalidPublicKey means the key is not an uncompressed EC point.
	ErrInvalidPublicKey = errors.New("invalid public key in encrypted header")
	// ErrInvalidSize means the declared plaintext size is unusable.
	ErrInvalidSize = errors.New("invalid plaintext size in encrypted header")
)

// Header holds every field needed to request a key and decrypt the payload.
type Header struct {
	// ID is the correlation id, formatted as a hyphenated UUID. See the package
	// comment: it is neither a UUID nor unique.
	ID string
	// PlaintextSize is the decrypted MP4 length declared in the header.
	PlaintextSize uint64

	VIN        string
	KeyID      uint32
	Timestamp  uint64
	WrappedKey []byte
	PublicKey  []byte
}

// ReadHeader parses the container header at the start of ra.
//
// A file that is not a Tesla container fails with ErrNotEncrypted, and one that
// is but is cut short fails with ErrTooShort. Neither is ever decrypted on a
// best-effort basis: a truncated clip that produced output would look like a
// success while yielding an unplayable file.
func ReadHeader(ra io.ReaderAt) (Header, error) {
	probe := make([]byte, probeSize)
	n, err := ra.ReadAt(probe, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return Header{}, fmt.Errorf("read header: %w", err)
	}
	probe = probe[:n]

	if err := checkContainer(probe); err != nil {
		return Header{}, err
	}

	h := Header{
		ID:            formatUUID(probe[idOffset : idOffset+idSize]),
		PlaintextSize: binary.BigEndian.Uint64(probe[:8]),
	}
	if h.PlaintextSize == 0 {
		return Header{}, ErrInvalidSize
	}

	meta := make([]byte, metadataEnd-metadataOffset)
	if n, err := ra.ReadAt(meta, metadataOffset); err != nil && !errors.Is(err, io.EOF) {
		return Header{}, fmt.Errorf("read ownership metadata: %w", err)
	} else if n < len(meta) {
		return Header{}, fmt.Errorf("%w: ownership metadata is incomplete", ErrTooShort)
	}

	field := func(off, size int) []byte { return meta[off-metadataOffset : off-metadataOffset+size] }

	publicKey := field(publicKeyOffset, publicKeySize)
	if publicKey[0] != 0x04 {
		return Header{}, ErrInvalidPublicKey
	}

	vin := string(bytes.TrimRight(field(vinOffset, vinSize), "\x00"))
	if len(vin) != vinSize || !isASCII(vin) {
		return Header{}, ErrInvalidVIN
	}

	h.VIN = vin
	h.KeyID = binary.BigEndian.Uint32(field(keyIDOffset, keyIDSize))
	h.Timestamp = binary.BigEndian.Uint64(field(timestampOffset, timestampSize))
	h.PublicKey = bytes.Clone(publicKey)
	h.WrappedKey = bytes.Clone(field(wrappedKeyOffset, wrappedKeySize))

	return h, nil
}

// checkContainer decides whether probe is the start of a Tesla container,
// distinguishing "this is something else" from "this one is cut short".
func checkContainer(probe []byte) error {
	// The metadata offset field is the container's signature. Without it there
	// is nothing to say the file was ever encrypted.
	if len(probe) < metadataOffsetField+4 {
		return ErrNotEncrypted
	}
	if binary.BigEndian.Uint32(probe[metadataOffsetField:metadataOffsetField+4]) != metadataOffset {
		return ErrNotEncrypted
	}

	// Signature present, so it is one of ours: anything missing now is damage.
	if len(probe) < probeSize {
		return fmt.Errorf("%w: %d of %d header bytes", ErrTooShort, len(probe), probeSize)
	}
	// An all-zero key_id means the metadata page was never written, which is
	// what a clip interrupted mid-write looks like.
	if bytes.Equal(probe[keyIDOffset:keyIDOffset+keyIDSize], make([]byte, keyIDSize)) {
		return fmt.Errorf("%w: ownership metadata was never written", ErrTooShort)
	}

	return nil
}

// formatUUID renders 16 raw bytes in the standard 4-2-2-2-6 grouping.
func formatUUID(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}
