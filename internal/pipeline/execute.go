package pipeline

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/container"
	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/tesla"
)

// writeBufferSize is the buffer used when writing decrypted output.
const writeBufferSize = 1 << 20

const (
	// dirPerm keeps output directories private: they hold personal footage.
	dirPerm = 0o700
	// tempPattern names the work-in-progress file. It deliberately lacks an
	// .mp4 extension so a leftover is never mistaken for a decrypted clip.
	tempPattern = ".tesdecrypt-*"
)

// maxConsecutiveBatchFailures stops a run whose key requests keep failing,
// rather than retrying every batch for hours against a broken endpoint.
const maxConsecutiveBatchFailures = 3

// keyFetcher is the part of tesla.Client the pipeline needs, so tests can
// supply their own.
type keyFetcher interface {
	FetchKeys(ctx context.Context, items []tesla.Item) (tesla.KeySet, error)
}

// Config controls a decryption run.
type Config struct {
	InputDir  string
	OutputDir string

	// BatchSize is how many clips share one key request.
	BatchSize int
	// Workers is how many clips are decrypted concurrently.
	Workers int
	// SkipExisting leaves clips already present in the output directory alone.
	SkipExisting bool
	// DryRun fetches keys but writes nothing.
	DryRun bool
	// Remux pipes each decrypted clip through ffmpeg.
	Remux bool

	// Client fetches the per-file keys.
	Client keyFetcher
}

// EventKind classifies a progress event.
type EventKind int

const (
	// EventDone reports a clip decrypted successfully.
	EventDone EventKind = iota
	// EventFailed reports a clip that could not be decrypted.
	EventFailed
	// EventSkipped reports a file that was not an encrypted clip at all, such
	// as an MP4 that had already been decrypted into the input tree.
	EventSkipped
)

// Event is a single progress update. Events arrive out of order because clips
// are decrypted concurrently.
type Event struct {
	Kind EventKind
	// Rel is the clip's path relative to the input directory.
	Rel string
	// Bytes is the decrypted size, for EventDone.
	Bytes int64
	// Err is why the clip failed or was skipped.
	Err error
}

// Summary is the outcome of a run.
type Summary struct {
	Decrypted    int
	Failed       int
	Skipped      int
	BytesWritten int64
}

// headed is a clip whose header has been read. Carrying the header alongside
// the job means it is read from disk exactly once, even when a clip has to be
// deferred to a later batch.
type headed struct {
	Job
	header container.Header
}

// keyedJob is a clip ready to decrypt.
type keyedJob struct {
	headed
	key []byte
}

// Execute decrypts every job, calling emit for each clip as it finishes. Keys
// for the next batch are fetched while the current batch is still decrypting.
//
// emit may be called concurrently from several goroutines, so an implementation
// that accumulates state must do its own synchronisation.
//
// Per-clip failures are reported through emit and counted in the Summary; only
// a fatal condition, such as an expired token, returns an error.
func Execute(ctx context.Context, cfg Config, jobs []Job, emit func(Event)) (Summary, error) {
	var (
		mu  sync.Mutex
		sum Summary
	)

	record := func(ev Event) {
		mu.Lock()
		switch ev.Kind {
		case EventDone:
			sum.Decrypted++
			sum.BytesWritten += ev.Bytes
		case EventFailed:
			sum.Failed++
		case EventSkipped:
			sum.Skipped++
		}
		mu.Unlock()

		if emit != nil {
			emit(ev)
		}
	}

	if len(jobs) == 0 {
		return sum, nil
	}

	g, ctx := errgroup.WithContext(ctx)
	work := make(chan keyedJob)

	g.Go(func() error {
		defer close(work)
		return fetchKeys(ctx, cfg, jobs, work, record)
	})

	for range max(1, cfg.Workers) {
		g.Go(func() error {
			for kj := range work {
				written, err := decryptOne(ctx, cfg, kj)
				if err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					record(Event{Kind: EventFailed, Rel: kj.Rel, Err: err})
					continue
				}
				record(Event{Kind: EventDone, Rel: kj.Rel, Bytes: written})
			}
			return nil
		})
	}

	err := g.Wait()
	return sum, err
}

// fetchKeys requests keys batch by batch and feeds the decrypt workers.
//
// Every clip's header is read exactly once: clips deferred because their id
// collides keep their header in the carry list.
func fetchKeys(ctx context.Context, cfg Config, jobs []Job, work chan<- keyedJob, record func(Event)) error {
	var (
		next     int
		carry    []headed
		batch    []headed
		failures int
	)

	for next < len(jobs) || len(carry) > 0 {
		batch, next, carry = nextBatch(cfg, jobs, next, carry, record)
		if len(batch) == 0 {
			continue
		}

		keys, err := cfg.Client.FetchKeys(ctx, itemsFor(batch))
		if err != nil {
			// An expired token affects every remaining clip, so stop at once.
			if errors.Is(err, tesla.ErrUnauthorized) || ctx.Err() != nil {
				return err
			}
			if failures++; failures >= maxConsecutiveBatchFailures {
				return fmt.Errorf("giving up after %d consecutive failed key requests: %w", failures, err)
			}
			for _, h := range batch {
				record(Event{Kind: EventFailed, Rel: h.Rel, Err: err})
			}
			continue
		}
		failures = 0

		if err := dispatch(ctx, batch, keys, work, record); err != nil {
			return err
		}
	}

	return nil
}

// nextBatch assembles the next key request, drawing first from the clips a
// previous batch deferred. Ids within a request must be unique: the API matches
// results to items by id, and every clip of the same size shares one.
//
// It returns the batch, the new position in jobs, and the clips still deferred.
// Each call consumes at least one clip, from jobs or from carry, so the caller's
// loop always terminates.
func nextBatch(
	cfg Config,
	jobs []Job,
	next int,
	carry []headed,
	record func(Event),
) (batch []headed, newNext int, newCarry []headed) {
	size := max(1, cfg.BatchSize)
	seen := make(map[string]bool, size)
	batch = make([]headed, 0, size)

	for _, h := range carry {
		if len(batch) < size && !seen[h.header.ID] {
			seen[h.header.ID] = true
			batch = append(batch, h)
			continue
		}
		newCarry = append(newCarry, h)
	}

	for next < len(jobs) && len(batch) < size {
		job := jobs[next]
		next++

		header, err := readHeader(job.Src)
		if err != nil {
			record(headerEvent(job, err))
			continue
		}
		if seen[header.ID] {
			newCarry = append(newCarry, headed{Job: job, header: header})
			continue
		}

		seen[header.ID] = true
		batch = append(batch, headed{Job: job, header: header})
	}

	return batch, next, newCarry
}

// dispatch hands each clip in the batch to a worker, in batch order so that a
// run is reproducible.
func dispatch(
	ctx context.Context,
	batch []headed,
	keys tesla.KeySet,
	work chan<- keyedJob,
	record func(Event),
) error {
	for _, h := range batch {
		key, ok := keys.Keys[h.header.ID]
		if !ok {
			msg := keys.Errors[h.header.ID]
			if msg == "" {
				msg = "no key returned by the API"
			}
			record(Event{Kind: EventFailed, Rel: h.Rel, Err: errors.New(msg)})
			continue
		}

		select {
		case work <- keyedJob{headed: h, key: key}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// headerEvent classifies a header failure: a file that was never encrypted is
// skipped rather than counted as a failure, so an already-decrypted MP4 sitting
// in the input tree does not fail the run.
func headerEvent(job Job, err error) Event {
	if errors.Is(err, container.ErrNotEncrypted) {
		return Event{Kind: EventSkipped, Rel: job.Rel, Err: err}
	}
	return Event{Kind: EventFailed, Rel: job.Rel, Err: err}
}

// readHeader parses the container header of a clip. It is a variable so tests
// can count how many times each clip is read from disk.
var readHeader = readHeaderFromDisk

func readHeaderFromDisk(path string) (container.Header, error) {
	f, err := os.Open(path)
	if err != nil {
		return container.Header{}, err
	}
	defer f.Close() //nolint:errcheck // Read-only handle.

	return container.ReadHeader(f)
}

// itemsFor builds the key-request items for a batch.
func itemsFor(batch []headed) []tesla.Item {
	items := make([]tesla.Item, 0, len(batch))
	for _, h := range batch {
		items = append(items, tesla.Item{
			ID:         h.header.ID,
			VIN:        h.header.VIN,
			KeyID:      h.header.KeyID,
			Timestamp:  h.header.Timestamp,
			WrappedKey: base64.StdEncoding.EncodeToString(h.header.WrappedKey),
			PublicKey:  base64.StdEncoding.EncodeToString(h.header.PublicKey),
		})
	}
	return items
}

// decryptOne decrypts a single clip through a temporary file, so an interrupted
// run never leaves a half-written MP4 behind and never writes through a symlink
// planted at the destination.
func decryptOne(ctx context.Context, cfg Config, kj keyedJob) (int64, error) {
	if cfg.DryRun {
		return 0, nil
	}

	dir := filepath.Dir(kj.Dst)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return 0, fmt.Errorf("create output directory: %w", err)
	}

	written, decrypted, err := decryptToTemp(ctx, dir, kj)
	if decrypted != "" {
		defer os.Remove(decrypted) //nolint:errcheck // No-op once renamed away.
	}
	if err != nil {
		return 0, err
	}

	final := decrypted
	if cfg.Remux {
		remuxed, rerr := remuxToTemp(ctx, dir, decrypted)
		if remuxed != "" {
			defer os.Remove(remuxed) //nolint:errcheck // No-op once renamed away.
		}
		if rerr != nil {
			return 0, rerr
		}
		final = remuxed
	}

	if err := os.Rename(final, kj.Dst); err != nil {
		return 0, fmt.Errorf("finalise output: %w", err)
	}

	return written, nil
}

// decryptToTemp streams the decrypted clip into a fresh temporary file in dir
// and returns its path, which is non-empty whenever the file was created.
func decryptToTemp(ctx context.Context, dir string, kj keyedJob) (int64, string, error) {
	src, err := os.Open(kj.Src)
	if err != nil {
		return 0, "", err
	}
	defer src.Close() //nolint:errcheck // Read-only handle.

	info, err := src.Stat()
	if err != nil {
		return 0, "", err
	}

	// CreateTemp gives an unpredictable name, O_EXCL, and mode 0600.
	dst, err := os.CreateTemp(dir, tempPattern)
	if err != nil {
		return 0, "", fmt.Errorf("create temporary file: %w", err)
	}
	defer dst.Close() //nolint:errcheck // Closed explicitly on the success path.
	path := dst.Name()

	buf := bufio.NewWriterSize(dst, writeBufferSize)
	written, err := container.Decrypt(ctx, buf, src, info.Size(), kj.header, kj.key)
	if err != nil {
		return written, path, err
	}
	if err := buf.Flush(); err != nil {
		return written, path, fmt.Errorf("flush output: %w", err)
	}
	if err := dst.Close(); err != nil {
		return written, path, fmt.Errorf("close output: %w", err)
	}

	return written, path, nil
}

// remuxToTemp remuxes src into a fresh temporary file in dir.
func remuxToTemp(ctx context.Context, dir, src string) (string, error) {
	dst, err := os.CreateTemp(dir, tempPattern)
	if err != nil {
		return "", fmt.Errorf("create temporary file: %w", err)
	}

	path := dst.Name()
	if err := dst.Close(); err != nil {
		return path, fmt.Errorf("close temporary file: %w", err)
	}

	if err := Remux(ctx, src, path); err != nil {
		return path, err
	}
	return path, nil
}
