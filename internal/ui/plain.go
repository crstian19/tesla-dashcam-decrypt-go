package ui

import (
	"fmt"
	"io"
	"strconv"
	"sync"

	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/pipeline"
)

// Plain writes one line per clip, with no cursor movement or colour. It is used
// when output is redirected to a file, a pipe or a cron log.
type Plain struct {
	w io.Writer

	mu    sync.Mutex
	total int
	seen  int
}

// NewPlain returns a Reporter writing plain lines to w.
func NewPlain(w io.Writer) *Plain {
	return &Plain{w: w}
}

// Start announces the number of clips to process.
func (p *Plain) Start(total int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.total = total
	writeLine(p.w, fmt.Sprintf("decrypting %d clip(s)", total))
}

// Emit reports one finished clip.
func (p *Plain) Emit(ev pipeline.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.seen++
	prefix := fmt.Sprintf("[%*d/%d]", len(strconv.Itoa(p.total)), p.seen, p.total)
	rel := sanitizeField(ev.Rel)

	switch ev.Kind {
	case pipeline.EventFailed:
		writeLine(p.w, fmt.Sprintf("%s fail %s: %s", prefix, rel, errText(ev.Err)))
	case pipeline.EventSkipped:
		writeLine(p.w, fmt.Sprintf("%s skip %s: %s", prefix, rel, errText(ev.Err)))
	default:
		writeLine(p.w, fmt.Sprintf("%s ok   %s (%s)", prefix, rel, humanBytes(ev.Bytes)))
	}
}

// Finish prints the closing summary.
func (p *Plain) Finish(sum pipeline.Summary, outputDir string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	line := fmt.Sprintf("done: %d decrypted, %d failed", sum.Decrypted, sum.Failed)
	if sum.Skipped > 0 {
		line += fmt.Sprintf(", %d not encrypted", sum.Skipped)
	}
	line += fmt.Sprintf(", %s written to %s", humanBytes(sum.BytesWritten), sanitize(outputDir))

	writeLine(p.w, line)
}
