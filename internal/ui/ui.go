// Package ui renders the progress of a decryption run, either as an animated
// Bubble Tea view on a terminal or as plain lines when output is redirected.
package ui

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"

	"charm.land/lipgloss/v2"
	"golang.org/x/term"

	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/pipeline"
)

// maxFieldWidth truncates untrusted text so one long value cannot wreck the
// layout.
const maxFieldWidth = 120

// Reporter renders progress for a run.
type Reporter interface {
	// Start announces how many clips will be processed.
	Start(total int)
	// Emit reports one finished clip. Safe to call from any goroutine.
	Emit(ev pipeline.Event)
	// Finish tears down the display and prints the summary.
	Finish(sum pipeline.Summary, outputDir string)
}

// Styles are the colours used across the CLI. ANSI base colours are used so the
// output stays readable on both light and dark terminals.
type Styles struct {
	Title   lipgloss.Style
	Subtle  lipgloss.Style
	Success lipgloss.Style
	Failure lipgloss.Style
	Skipped lipgloss.Style
	Path    lipgloss.Style
	Size    lipgloss.Style
}

// DefaultStyles returns the house styling.
func DefaultStyles() Styles {
	return Styles{
		Title:   lipgloss.NewStyle().Bold(true),
		Subtle:  lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
		Success: lipgloss.NewStyle().Foreground(lipgloss.Color("2")),
		Failure: lipgloss.NewStyle().Foreground(lipgloss.Color("1")),
		Skipped: lipgloss.NewStyle().Foreground(lipgloss.Color("3")),
		Path:    lipgloss.NewStyle(),
		Size:    lipgloss.NewStyle().Foreground(lipgloss.Color("8")),
	}
}

// New returns the richest reporter the output supports: the Bubble Tea view on
// a terminal, plain lines otherwise.
func New(out *os.File, plain bool, onInterrupt func()) Reporter {
	if plain || !isTerminal(out) {
		return NewPlain(out)
	}
	return NewTUI(out, onInterrupt)
}

// Header prints what the run is about to do, before any progress is shown.
func Header(w io.Writer, styles Styles, inputDir string, plan pipeline.Plan) {
	writeLine(w, styles.Title.Render("Scanning ")+styles.Path.Render(sanitize(inputDir)))

	summary := fmt.Sprintf("%d clip(s) found", plan.Discovered)
	if n := len(plan.Skipped); n > 0 {
		summary += fmt.Sprintf(", %d already decrypted", n)
	}
	summary += fmt.Sprintf(", %d to decrypt", len(plan.Jobs))

	writeLine(w, styles.Subtle.Render(summary))
}

// Note prints an aside, such as the dry-run warning.
func Note(w io.Writer, styles Styles, text string) {
	writeLine(w, styles.Subtle.Render(text))
}

// isTerminal reports whether w is an interactive terminal.
func isTerminal(w *os.File) bool {
	return term.IsTerminal(int(w.Fd()))
}

// sanitize strips control characters so text cannot drive the terminal.
//
// Paths the user typed are only passed through here: they are trusted enough
// to print in full, and truncating them would hide where the output went.
func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r == unicode.ReplacementChar, unicode.IsControl(r):
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}

	return b.String()
}

// sanitizeField is sanitize plus a length cap, for values that come from the
// drive or from the API. Escape sequences there could rewrite earlier lines or
// fake the final summary, and an over-long value would wreck the layout.
func sanitizeField(s string) string {
	out := sanitize(s)
	if len([]rune(out)) > maxFieldWidth {
		out = string([]rune(out)[:maxFieldWidth-1]) + "…"
	}
	return out
}

// errText renders an event's error as a single safe line.
func errText(err error) string {
	if err == nil {
		return "unknown error"
	}
	return sanitizeField(err.Error())
}

// humanBytes formats a byte count for humans.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}

	div, exp := int64(unit), 0
	for size := n / unit; size >= unit && exp < 3; size /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

// writeLine writes s followed by a newline, ignoring write errors: a broken
// pipe on the progress display must not fail the run.
func writeLine(w io.Writer, s string) {
	fmt.Fprintln(w, s) //nolint:errcheck // Progress output is best-effort.
}
