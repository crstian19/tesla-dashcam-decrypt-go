package container

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // Matching the format under test.
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// testKey is the key the golden fixture was encrypted with.
var testKey = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// TestPageIV checks the IV derivation against vectors computed independently
// with Python's hashlib, which is what the reference implementation uses.
func TestPageIV(t *testing.T) {
	t.Parallel()

	rootIV := md5.Sum(testKey) //nolint:gosec // Matching the format under test.
	if got := hex.EncodeToString(rootIV[:]); got != "1ac1ef01e96caf1be0d329331a4fc2a8" {
		t.Fatalf("root IV = %s, want 1ac1ef01e96caf1be0d329331a4fc2a8", got)
	}

	tests := []struct {
		page uint64
		want string
	}{
		{0, "cd096e1db464e9b4c91e51419090606b"},
		{1, "41e2d33e4f39f1b90c7b306fc13cb684"},
		{2, "502b4d57690da26dfd03852339ce4733"},
		{9, "ea706b3d1e79a424baa00a982a3eabc4"},
		{10, "5ce066bcdaf9ef30ca01ce592e8d196e"},
		{12345, "4e0ad9f8ed3c8b1c943f3bc6f6a4a6a6"},
	}

	for _, tc := range tests {
		iv := pageIV(rootIV[:], tc.page)
		if got := hex.EncodeToString(iv[:]); got != tc.want {
			t.Errorf("pageIV(page %d) = %s, want %s", tc.page, got, tc.want)
		}
	}
}

// TestDecryptGoldenClip decrypts a fixture encrypted with OpenSSL, so the test
// exercises the format rather than this package's own encryption.
func TestDecryptGoldenClip(t *testing.T) {
	t.Parallel()

	encrypted := readFixture(t, "real_clip.enc")
	want := readFixture(t, "real_clip.mp4")

	header, err := ReadHeader(bytes.NewReader(encrypted))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if header.PlaintextSize != uint64(len(want)) {
		t.Fatalf("PlaintextSize = %d, want %d", header.PlaintextSize, len(want))
	}

	var got bytes.Buffer
	n, err := Decrypt(t.Context(), &got, bytes.NewReader(encrypted), int64(len(encrypted)), header, testKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if n != int64(len(want)) {
		t.Errorf("wrote %d bytes, want %d", n, len(want))
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Error("decrypted output does not match the expected plaintext")
	}
}

// TestReadHeaderGoldenClip checks every field parsed from the fixture header.
func TestReadHeaderGoldenClip(t *testing.T) {
	t.Parallel()

	header, err := ReadHeader(bytes.NewReader(readFixture(t, "real_clip.enc")))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}

	// The id overlaps the plaintext size field, so it starts with 0x1388 = 5000.
	if want := "00001388-3c81-b7f5-0000-0002000d0000"; header.ID != want {
		t.Errorf("ID = %q, want %q", header.ID, want)
	}
	if want := "5YJ3E1EA7KF000001"; header.VIN != want {
		t.Errorf("VIN = %q, want %q", header.VIN, want)
	}
	if header.KeyID != 1 {
		t.Errorf("KeyID = %d, want 1", header.KeyID)
	}
	if header.Timestamp != 1782000000 {
		t.Errorf("Timestamp = %d, want 1782000000", header.Timestamp)
	}
	if len(header.PublicKey) != publicKeySize || header.PublicKey[0] != 0x04 {
		t.Errorf("PublicKey = %d bytes starting %#x, want %d starting 0x04",
			len(header.PublicKey), header.PublicKey[0], publicKeySize)
	}
	if len(header.WrappedKey) != wrappedKeySize {
		t.Errorf("WrappedKey = %d bytes, want %d", len(header.WrappedKey), wrappedKeySize)
	}
}

// TestIDCollision documents that clips of identical plaintext size share an id.
// The pipeline must never put two of them in the same key request.
func TestIDCollision(t *testing.T) {
	t.Parallel()

	encrypted := readFixture(t, "real_clip.enc")

	// A different clip, same plaintext size: only the payload differs.
	other := bytes.Clone(encrypted)
	for i := payloadOffset; i < len(other); i++ {
		other[i] ^= 0xFF
	}

	first, err := ReadHeader(bytes.NewReader(encrypted))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	second, err := ReadHeader(bytes.NewReader(other))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}

	if first.ID != second.ID {
		t.Fatalf("expected colliding ids, got %q and %q", first.ID, second.ID)
	}
}

// TestReadHeaderRejectsBadInput covers the two ways a file can fail to be a
// usable clip: it is not one of Tesla's containers, or it is a damaged one.
func TestReadHeaderRejectsBadInput(t *testing.T) {
	t.Parallel()

	valid := readFixture(t, "real_clip.enc")

	tests := []struct {
		name   string
		mutate func([]byte) []byte
		want   error
	}{
		{
			name:   "an ordinary already-decrypted mp4",
			mutate: func([]byte) []byte { return []byte("\x00\x00\x00\x0cftypisom plus some payload") },
			want:   ErrNotEncrypted,
		},
		{
			name:   "empty file",
			mutate: func([]byte) []byte { return nil },
			want:   ErrNotEncrypted,
		},
		{
			name:   "container signature present but header truncated",
			mutate: func(b []byte) []byte { return b[:100] },
			want:   ErrTooShort,
		},
		{
			name: "metadata page never written",
			mutate: func(b []byte) []byte {
				copy(b[keyIDOffset:keyIDOffset+keyIDSize], make([]byte, keyIDSize))
				return b
			},
			want: ErrTooShort,
		},
		{
			name:   "ownership metadata incomplete",
			mutate: func(b []byte) []byte { return b[:metadataOffset+8] },
			want:   ErrTooShort,
		},
		{
			name: "vin is not 17 characters",
			mutate: func(b []byte) []byte {
				copy(b[vinOffset:vinOffset+vinSize], make([]byte, vinSize))
				return b
			},
			want: ErrInvalidVIN,
		},
		{
			name: "public key is not an uncompressed point",
			mutate: func(b []byte) []byte {
				b[publicKeyOffset] = 0x02
				return b
			},
			want: ErrInvalidPublicKey,
		},
		{
			name: "plaintext size is zero",
			mutate: func(b []byte) []byte {
				binary.BigEndian.PutUint64(b[:8], 0)
				return b
			},
			want: ErrInvalidSize,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := ReadHeader(bytes.NewReader(tc.mutate(bytes.Clone(valid))))
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestTruncatedClipIsNeverSilentlyDecrypted is the regression test for a clip
// cut short on the drive: it must fail loudly rather than produce a short file
// that the run reports as a success.
func TestTruncatedClipIsNeverSilentlyDecrypted(t *testing.T) {
	t.Parallel()

	full := readFixture(t, "real_clip.enc")

	for _, size := range []int{50, 100, 1000, 4096, metadataOffset + 8, payloadOffset} {
		t.Run(strconv.Itoa(size)+" bytes", func(t *testing.T) {
			t.Parallel()

			truncated := full[:size]

			header, err := ReadHeader(bytes.NewReader(truncated))
			if err != nil {
				return // Rejected at the header, which is the outcome we want.
			}

			var out bytes.Buffer
			if _, err := Decrypt(t.Context(), &out, bytes.NewReader(truncated),
				int64(len(truncated)), header, testKey); err == nil {
				t.Errorf("truncated to %d bytes: decrypted %d bytes with no error", size, out.Len())
			}
		})
	}
}

// TestDecryptRejectsWrongKey covers the integrity check: CBC decrypts to noise
// under a wrong key instead of failing, so the ftyp box is what catches it.
func TestDecryptRejectsWrongKey(t *testing.T) {
	t.Parallel()

	encrypted := readFixture(t, "real_clip.enc")
	header, err := ReadHeader(bytes.NewReader(encrypted))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}

	wrongKey := bytes.Clone(testKey)
	wrongKey[0] ^= 0xFF

	var out bytes.Buffer
	n, err := Decrypt(t.Context(), &out, bytes.NewReader(encrypted), int64(len(encrypted)), header, wrongKey)
	if !errors.Is(err, ErrNotMP4) {
		t.Fatalf("error = %v, want ErrNotMP4", err)
	}
	if n != 0 || out.Len() != 0 {
		t.Errorf("wrote %d bytes with a wrong key, want none", out.Len())
	}
}

func TestDecryptRejectsShortPayload(t *testing.T) {
	t.Parallel()

	encrypted := readFixture(t, "real_clip.enc")
	truncated := encrypted[:len(encrypted)-PageSize]

	header, err := ReadHeader(bytes.NewReader(truncated))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}

	_, err = Decrypt(t.Context(), &bytes.Buffer{}, bytes.NewReader(truncated),
		int64(len(truncated)), header, testKey)
	if !errors.Is(err, ErrShortPayload) {
		t.Errorf("error = %v, want %v", err, ErrShortPayload)
	}
}

func TestDecryptRejectsBadKeyLength(t *testing.T) {
	t.Parallel()

	encrypted := readFixture(t, "real_clip.enc")
	header, err := ReadHeader(bytes.NewReader(encrypted))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}

	_, err = Decrypt(t.Context(), &bytes.Buffer{}, bytes.NewReader(encrypted),
		int64(len(encrypted)), header, []byte("short"))
	if err == nil {
		t.Error("expected an error for an invalid key length")
	}
}

// TestDecryptHonoursCancellation checks a cancelled run stops mid-clip.
func TestDecryptHonoursCancellation(t *testing.T) {
	t.Parallel()

	encrypted := readFixture(t, "real_clip.enc")
	header, err := ReadHeader(bytes.NewReader(encrypted))
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = Decrypt(ctx, &bytes.Buffer{}, bytes.NewReader(encrypted), int64(len(encrypted)), header, testKey)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}
