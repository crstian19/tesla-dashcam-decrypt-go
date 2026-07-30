package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/pipeline"
)

func TestHumanBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
		// Beyond terabytes the unit stops scaling rather than running off the
		// end of the unit string.
		{1125899906842624, "1024.0 TB"},
	}

	for _, tc := range tests {
		if got := humanBytes(tc.bytes); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.bytes, got, tc.want)
		}
	}
}

// TestSanitize covers the escape sequences an attacker-controlled filename or
// API message could otherwise write straight to the terminal.
func TestSanitize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is untouched", "SentryClips/front.mp4", "SentryClips/front.mp4"},
		{"accents survive", "cámara trasera.mp4", "cámara trasera.mp4"},
		{"escape sequences are neutralised", "a\x1b[2Kb", "a?[2Kb"},
		{"newlines cannot forge a line", "clip\nDone: 0 failed", "clip?Done: 0 failed"},
		{"carriage returns cannot rewrite", "clip\roops", "clip?oops"},
		{"tabs become spaces", "a\tb", "a b"},
		{"OSC sequences are neutralised", "\x1b]52;c;cGF5bG9hZA==\x07", "?]52;c;cGF5bG9hZA==?"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := sanitize(tc.in); got != tc.want {
				t.Errorf("sanitize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeFieldTruncatesLongValues(t *testing.T) {
	t.Parallel()

	got := sanitizeField(strings.Repeat("x", 500))
	if n := len([]rune(got)); n != maxFieldWidth {
		t.Errorf("length = %d, want %d", n, maxFieldWidth)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated value should be marked with an ellipsis, got %q", got[len(got)-5:])
	}
}

// TestSanitizeDoesNotTruncate checks a long path the user typed is printed in
// full, so the summary always shows where the output went.
func TestSanitizeDoesNotTruncate(t *testing.T) {
	t.Parallel()

	long := "/media/" + strings.Repeat("nested/", 40) + "TeslaCam"
	if got := sanitize(long); got != long {
		t.Errorf("sanitize shortened a user-supplied path to %d chars", len(got))
	}
}

func TestErrText(t *testing.T) {
	t.Parallel()

	if got := errText(nil); got != "unknown error" {
		t.Errorf("errText(nil) = %q", got)
	}
	if got := errText(errors.New("boom\x1b[1m")); got != "boom?[1m" {
		t.Errorf("errText did not sanitize: %q", got)
	}
}

func TestPlainReporter(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	r := NewPlain(&buf)

	r.Start(3)
	r.Emit(pipeline.Event{Kind: pipeline.EventDone, Rel: "front.mp4", Bytes: 1536})
	r.Emit(pipeline.Event{Kind: pipeline.EventFailed, Rel: "back.mp4", Err: errors.New("no key returned")})
	r.Emit(pipeline.Event{Kind: pipeline.EventSkipped, Rel: "old.mp4", Err: errors.New("not an encrypted Tesla clip")})
	r.Finish(pipeline.Summary{Decrypted: 1, Failed: 1, Skipped: 1, BytesWritten: 1536}, "/out")

	want := []string{
		"decrypting 3 clip(s)",
		"[1/3] ok   front.mp4 (1.5 KB)",
		"[2/3] fail back.mp4: no key returned",
		"[3/3] skip old.mp4: not an encrypted Tesla clip",
		"done: 1 decrypted, 1 failed, 1 not encrypted, 1.5 KB written to /out",
	}

	got := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(got), len(want), buf.String())
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i+1, got[i], want[i])
		}
	}
}

// TestPlainReporterAlignsCounter checks the counter column stays aligned once
// the total reaches three digits, which is the usual case for a real drive.
func TestPlainReporterAlignsCounter(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	r := NewPlain(&buf)
	r.Start(120)
	r.Emit(pipeline.Event{Kind: pipeline.EventDone, Rel: "a.mp4", Bytes: 10})

	if want := "[  1/120] ok   a.mp4 (10 B)"; !strings.Contains(buf.String(), want) {
		t.Errorf("output = %q, want it to contain %q", buf.String(), want)
	}
}

// TestPlainReporterIsConcurrencySafe mirrors how the pipeline calls Emit: from
// several goroutines at once.
func TestPlainReporterIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	r := NewPlain(&buf)
	r.Start(50)

	done := make(chan struct{})
	for i := range 5 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 10 {
				r.Emit(pipeline.Event{Kind: pipeline.EventDone, Rel: "clip.mp4", Bytes: int64(i)})
			}
		}()
	}
	for range 5 {
		<-done
	}

	if n := strings.Count(buf.String(), "\n"); n != 51 {
		t.Errorf("wrote %d lines, want 51", n)
	}
}

func TestHeader(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	Header(&buf, DefaultStyles(), "/media/TESLA", pipeline.Plan{
		Discovered: 10,
		Skipped:    []string{"a.mp4", "b.mp4"},
		Jobs:       make([]pipeline.Job, 8),
	})

	out := buf.String()
	for _, want := range []string{"/media/TESLA", "10 clip(s) found", "2 already decrypted", "8 to decrypt"} {
		if !strings.Contains(out, want) {
			t.Errorf("header output %q is missing %q", out, want)
		}
	}
}

func TestLogLine(t *testing.T) {
	t.Parallel()

	styles := DefaultStyles()

	tests := []struct {
		name string
		ev   pipeline.Event
		want []string
	}{
		{
			name: "success",
			ev:   pipeline.Event{Kind: pipeline.EventDone, Rel: "front.mp4", Bytes: 2048},
			want: []string{"✓", "front.mp4", "2.0 KB"},
		},
		{
			name: "failure",
			ev:   pipeline.Event{Kind: pipeline.EventFailed, Rel: "back.mp4", Err: errors.New("nope")},
			want: []string{"✗", "back.mp4", "nope"},
		},
		{
			name: "skipped",
			ev:   pipeline.Event{Kind: pipeline.EventSkipped, Rel: "old.mp4", Err: errors.New("not encrypted")},
			want: []string{"−", "old.mp4", "not encrypted"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := logLine(styles, tc.ev)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("logLine = %q, missing %q", got, want)
				}
			}
		})
	}
}
