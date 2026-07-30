package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ffmpegBinary is the remuxer invoked when --remux is set.
const ffmpegBinary = "ffmpeg"

// HasFFmpeg reports whether ffmpeg is on PATH.
func HasFFmpeg() bool {
	_, err := exec.LookPath(ffmpegBinary)
	return err == nil
}

// Remux losslessly rewrites src into dst, moving the MP4 index to the front so
// players that choke on Tesla's container layout can open the file.
//
// Both paths are made absolute first: a relative path starting with "-" would
// otherwise reach ffmpeg as an option rather than a filename.
func Remux(ctx context.Context, src, dst string) error {
	src, err := filepath.Abs(src)
	if err != nil {
		return fmt.Errorf("resolve input path: %w", err)
	}
	dst, err = filepath.Abs(dst)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}

	cmd := exec.CommandContext(ctx, ffmpegBinary,
		"-y",
		"-loglevel", "error",
		// Pin the demuxer and forbid non-file protocols: the input is
		// attacker-influenced media.
		"-f", "mp4",
		"-protocol_whitelist", "file",
		"-i", src,
		"-c", "copy",
		"-movflags", "faststart",
		"-f", "mp4",
		dst,
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if detail := lastLine(stderr.String()); detail != "" {
			return fmt.Errorf("ffmpeg: %w: %s", err, detail)
		}
		return fmt.Errorf("ffmpeg: %w", err)
	}
	return nil
}

// lastLine returns the final non-empty line, which is where ffmpeg puts the
// actual reason it failed.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			return line
		}
	}
	return ""
}
