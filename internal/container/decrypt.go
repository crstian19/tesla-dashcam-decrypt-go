package container

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" //nolint:gosec // MD5 is dictated by the container's IV derivation.
	"errors"
	"fmt"
	"io"
	"strconv"
)

var (
	// ErrPartialPage means the payload ended mid-page.
	ErrPartialPage = errors.New("encrypted page is not a full page")
	// ErrShortPayload means the payload held less data than the header declares.
	ErrShortPayload = errors.New("payload is shorter than the declared plaintext size")
	// ErrNotMP4 means the decrypted output is not an MP4, which means the key
	// was wrong: CBC has no integrity check, so it decrypts to noise rather
	// than failing.
	ErrNotMP4 = errors.New("decrypted output is not an MP4, the key does not match")
)

// readBufferSize is the read-ahead used when streaming the payload.
const readBufferSize = 1 << 20

// ftypOffset is where an ISO base media file must carry its "ftyp" box type.
const ftypOffset = 4

// ftypBox is the box type every MP4 opens with.
var ftypBox = []byte("ftyp")

// Decrypt writes the decrypted MP4 for the container in src to dst and returns
// the number of bytes written. size is the total size of the container file.
//
// Cancelling ctx stops the run between pages, so a large clip does not have to
// finish before the caller can shut down.
func Decrypt(ctx context.Context, dst io.Writer, src io.ReaderAt, size int64, h Header, key []byte) (int64, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, fmt.Errorf("build cipher: %w", err)
	}
	if size <= payloadOffset {
		return 0, fmt.Errorf("%w: no payload after the header", ErrTooShort)
	}

	payload := bufio.NewReaderSize(
		io.NewSectionReader(src, payloadOffset, size-payloadOffset), readBufferSize)

	return decryptPages(ctx, dst, payload, block, key, h.PlaintextSize)
}

// decryptPages decrypts the eCryptfs-style payload. Each 4096-byte page is
// AES-CBC encrypted under a per-page IV derived from the file key and the
// zero-based page number; no IV is stored in the file.
func decryptPages(
	ctx context.Context,
	dst io.Writer,
	src io.Reader,
	block cipher.Block,
	key []byte,
	plaintextSize uint64,
) (int64, error) {
	rootIV := md5.Sum(key) //nolint:gosec // Dictated by the format.
	page := make([]byte, PageSize)

	var written uint64
	for n := uint64(0); written < plaintextSize; n++ {
		if err := ctx.Err(); err != nil {
			return int64(written), err
		}

		switch _, err := io.ReadFull(src, page); {
		case errors.Is(err, io.EOF):
			return int64(written), fmt.Errorf("%w: got %d of %d bytes", ErrShortPayload, written, plaintextSize)
		case errors.Is(err, io.ErrUnexpectedEOF):
			return int64(written), fmt.Errorf("%w: page %d", ErrPartialPage, n)
		case err != nil:
			return int64(written), fmt.Errorf("read page %d: %w", n, err)
		}

		iv := pageIV(rootIV[:], n)
		cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(page, page)

		// The first page tells us whether the key was right at all.
		if n == 0 && !looksLikeMP4(page) {
			return 0, ErrNotMP4
		}

		out := page
		if remaining := plaintextSize - written; remaining < uint64(len(out)) {
			out = out[:remaining]
		}
		if _, err := dst.Write(out); err != nil {
			return int64(written), fmt.Errorf("write page %d: %w", n, err)
		}
		written += uint64(len(out))
	}

	return int64(written), nil
}

// looksLikeMP4 reports whether a decrypted first page opens with an ftyp box.
// Without it a wrong key yields a full-length file of noise, reported as a
// success, and the user only finds out when nothing plays.
func looksLikeMP4(page []byte) bool {
	if len(page) < ftypOffset+len(ftypBox) {
		return false
	}
	return bytes.Equal(page[ftypOffset:ftypOffset+len(ftypBox)], ftypBox)
}

// pageIV derives the IV for a page as MD5(MD5(key) + ascii(page)), the whole
// input zero-padded to 32 bytes.
func pageIV(rootIV []byte, page uint64) [md5.Size]byte {
	digits := strconv.FormatUint(page, 10)

	// 32 bytes covers every page number a real file can reach; the longer
	// branch just keeps the derivation well defined.
	material := make([]byte, max(32, len(rootIV)+len(digits)))
	copy(material, rootIV)
	copy(material[len(rootIV):], digits)

	return md5.Sum(material) //nolint:gosec // Dictated by the format.
}
