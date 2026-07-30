// Package containertest builds encrypted clips for tests.
//
// It is the only place that writes the container layout; internal/container is
// the only place that reads it. Keeping the writer here rather than duplicating
// offsets in each test package means a layout change breaks one file, and the
// round-trip tests in internal/container catch any drift between the two.
package containertest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" //nolint:gosec // Matching the container format.
	"encoding/binary"
	"slices"
	"strconv"
	"testing"

	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/container"
)

// Layout of the two header pages, mirroring the package comment of
// internal/container.
const (
	page = container.PageSize

	sizeOffset          = 0
	magicOffset         = 8
	versionOffset       = 16
	metadataOffsetField = 0x14

	keyIDOffset      = 0
	publicKeyOffset  = 4
	vinOffset        = 69
	timestampOffset  = 86
	wrappedKeyOffset = 94

	metadataOffset = 0x1000
)

// TestVIN is a syntactically valid but fictional VIN.
const TestVIN = "5YJ3E1EA7KF000001"

// TestTimestamp is the timestamp written into generated clips.
const TestTimestamp = 1782000000

// Clip returns an encrypted container holding plain, encrypted under key and
// declaring wrapped as its wrapped key.
func Clip(tb testing.TB, plain, key, wrapped []byte) []byte {
	tb.Helper()

	header := make([]byte, page)
	binary.BigEndian.PutUint64(header[sizeOffset:], uint64(len(plain)))
	copy(header[magicOffset:], []byte{0x3c, 0x81, 0xb7, 0xf5, 0x00, 0x00, 0x00, 0x02})
	binary.BigEndian.PutUint32(header[versionOffset:], 0x0d0000)
	binary.BigEndian.PutUint32(header[metadataOffsetField:], metadataOffset)

	metadata := make([]byte, page)
	binary.BigEndian.PutUint32(metadata[keyIDOffset:], 1)
	metadata[publicKeyOffset] = 0x04 // uncompressed EC point
	for i := range 64 {
		metadata[publicKeyOffset+1+i] = byte(i)
	}
	copy(metadata[vinOffset:], TestVIN)
	binary.BigEndian.PutUint64(metadata[timestampOffset:], TestTimestamp)
	copy(metadata[wrappedKeyOffset:], wrapped)

	return slices.Concat(header, metadata, encryptPages(tb, plain, key))
}

// MP4 returns deterministic plaintext of the given size that opens with a
// valid ftyp box, which is what the decryptor checks to detect a wrong key.
func MP4(size int, seed byte) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i*7) ^ seed
	}

	// A minimal ISO base media header: box length, then the ftyp box type.
	if len(out) >= 12 {
		binary.BigEndian.PutUint32(out[0:4], 12)
		copy(out[4:8], "ftyp")
		copy(out[8:12], "isom")
	}
	return out
}

// Key returns a deterministic 16-byte AES key for a seed.
func Key(seed byte) []byte {
	key := make([]byte, 16)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

// WrappedKey returns a deterministic 44-byte wrapped key for a seed. Tests use
// it to tell clips apart, since the API resolves keys by wrapped key.
func WrappedKey(seed byte) []byte {
	wrapped := make([]byte, 44)
	for i := range wrapped {
		wrapped[i] = seed ^ byte(i)
	}
	return wrapped
}

// encryptPages encrypts plain as 4096-byte pages, each under an IV derived from
// the key and the page number.
func encryptPages(tb testing.TB, plain, key []byte) []byte {
	tb.Helper()

	block, err := aes.NewCipher(key)
	if err != nil {
		tb.Fatalf("aes.NewCipher: %v", err)
	}

	padded := slices.Clone(plain)
	if rem := len(padded) % page; rem != 0 {
		padded = append(padded, make([]byte, page-rem)...)
	}

	rootIV := md5.Sum(key) //nolint:gosec // Matching the container format.
	out := make([]byte, len(padded))

	for i := 0; i*page < len(padded); i++ {
		material := make([]byte, 32)
		copy(material, rootIV[:])
		copy(material[len(rootIV):], strconv.Itoa(i))
		iv := md5.Sum(material) //nolint:gosec // Matching the container format.

		cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(
			out[i*page:(i+1)*page], padded[i*page:(i+1)*page])
	}

	return out
}
