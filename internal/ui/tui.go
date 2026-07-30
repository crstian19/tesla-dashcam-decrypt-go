package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"charm.land/bubbles/v2/progress"
	tea "charm.land/bubbletea/v2"

	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/pipeline"
)

// barWidth bounds for the progress bar, which tracks the terminal width.
const (
	minBarWidth = 10
	maxBarWidth = 48
	// barPadding is roughly the room taken by the counter next to the bar.
	barPadding = 28
)

// TUI renders progress as a live Bubble Tea view with a log of finished clips
// scrolling above it.
//
// If the program fails to start, every method falls back to Plain: a broken
// display must not swallow the run's output.
type TUI struct {
	out         *os.File
	styles      Styles
	onInterrupt func()

	prog *tea.Program
	done chan struct{}

	mu       sync.Mutex
	fallback *Plain
}

// NewTUI returns a Reporter drawing to out. onInterrupt is called when the user
// presses ctrl+c, so the caller can cancel the run.
func NewTUI(out *os.File, onInterrupt func()) *TUI {
	return &TUI{out: out, styles: DefaultStyles(), onInterrupt: onInterrupt}
}

// Start launches the progress view.
func (t *TUI) Start(total int) {
	m := &model{
		styles: t.styles,
		bar:    progress.New(progress.WithDefaultBlend(), progress.WithWidth(maxBarWidth)),
		total:  total,
		onQuit: t.onInterrupt,
	}

	t.prog = tea.NewProgram(m, tea.WithOutput(t.out))
	t.done = make(chan struct{})

	go func() {
		defer close(t.done)
		if _, err := t.prog.Run(); err != nil {
			t.degrade(total, err)
		}
	}()
}

// Emit reports one finished clip.
//
// The log line goes through the program's own message queue rather than a
// command returned from Update, so it is guaranteed to be rendered before the
// quit that Finish enqueues behind it.
func (t *TUI) Emit(ev pipeline.Event) {
	if plain := t.plain(); plain != nil {
		plain.Emit(ev)
		return
	}

	t.prog.Println(logLine(t.styles, ev))
	t.prog.Send(fileMsg{ev: ev})
}

// Finish stops the view and prints the summary below it.
func (t *TUI) Finish(sum pipeline.Summary, outputDir string) {
	if t.prog != nil {
		t.prog.Quit()
		<-t.done
	}
	if plain := t.plain(); plain != nil {
		plain.Finish(sum, outputDir)
		return
	}

	parts := []string{
		t.styles.Success.Render(fmt.Sprintf("✓ %d decrypted", sum.Decrypted)),
	}
	if sum.Failed > 0 {
		parts = append(parts, t.styles.Failure.Render(fmt.Sprintf("✗ %d failed", sum.Failed)))
	}
	if sum.Skipped > 0 {
		parts = append(parts, t.styles.Skipped.Render(fmt.Sprintf("%d not encrypted", sum.Skipped)))
	}
	if sum.BytesWritten > 0 {
		parts = append(parts, t.styles.Subtle.Render(humanBytes(sum.BytesWritten)))
	}

	writeLine(t.out, "")
	writeLine(t.out, strings.Join(parts, t.styles.Subtle.Render(" · ")))
	writeLine(t.out, t.styles.Subtle.Render("output: ")+t.styles.Path.Render(sanitize(outputDir)))
}

// degrade switches to plain output after the program failed to run.
func (t *TUI) degrade(total int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.fallback != nil {
		return
	}
	t.fallback = NewPlain(t.out)
	writeLine(t.out, t.styles.Failure.Render("progress display unavailable: "+errText(err)))
	t.fallback.Start(total)
}

// plain returns the fallback reporter once the view has failed, else nil.
func (t *TUI) plain() *Plain {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fallback
}

// fileMsg carries a finished clip into the Bubble Tea loop.
type fileMsg struct{ ev pipeline.Event }

// model is the progress view: a bar, a counter, and a printed line per clip.
type model struct {
	styles Styles
	bar    progress.Model

	total     int
	done      int
	failed    int
	cancelled bool

	onQuit func()
}

// Init implements tea.Model.
func (m *model) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.bar.SetWidth(min(max(msg.Width-barPadding, minBarWidth), maxBarWidth))

	case tea.KeyMsg:
		if s := msg.String(); s == "ctrl+c" || s == "q" {
			// Ask the run to stop; the view closes once it has unwound.
			m.cancelled = true
			if m.onQuit != nil {
				m.onQuit()
			}
		}

	case fileMsg:
		m.done++
		if msg.ev.Kind == pipeline.EventFailed {
			m.failed++
		}
	}

	return m, nil
}

// View implements tea.Model.
func (m *model) View() tea.View {
	var percent float64
	if m.total > 0 {
		percent = float64(m.done) / float64(m.total)
	}

	line := "  " + m.bar.ViewAs(percent) +
		"  " + m.styles.Subtle.Render(fmt.Sprintf("%d/%d", m.done, m.total))

	if m.failed > 0 {
		line += "  " + m.styles.Failure.Render(fmt.Sprintf("%d failed", m.failed))
	}
	if m.cancelled {
		line += "  " + m.styles.Subtle.Render("cancelling…")
	}

	return tea.NewView(line)
}

// logLine renders the log entry for a finished clip.
func logLine(styles Styles, ev pipeline.Event) string {
	switch ev.Kind {
	case pipeline.EventFailed:
		return fmt.Sprintf("  %s %s %s",
			styles.Failure.Render("✗"),
			styles.Path.Render(sanitizeField(ev.Rel)),
			styles.Failure.Render(errText(ev.Err)),
		)
	case pipeline.EventSkipped:
		return fmt.Sprintf("  %s %s %s",
			styles.Skipped.Render("−"),
			styles.Path.Render(sanitizeField(ev.Rel)),
			styles.Skipped.Render(errText(ev.Err)),
		)
	default:
		return fmt.Sprintf("  %s %s %s",
			styles.Success.Render("✓"),
			styles.Path.Render(sanitizeField(ev.Rel)),
			styles.Size.Render("("+humanBytes(ev.Bytes)+")"),
		)
	}
}
