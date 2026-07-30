package pipeline

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/container"
	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/containertest"
	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/tesla"
)

// fakeAPI stands in for Tesla's key endpoint. Keys are looked up by wrapped key
// rather than by item id, because ids are not unique across clips.
type fakeAPI struct {
	mu sync.Mutex

	keysByWrapped map[string][]byte
	reject        map[string]string
	// failFirst makes the first n requests fail, to exercise partial failure.
	failFirst int
	// err fails every request.
	err error

	requests       [][]tesla.Item
	sawDuplicateID bool
}

func (f *fakeAPI) FetchKeys(_ context.Context, items []tesla.Item) (tesla.KeySet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.requests = append(f.requests, slices.Clone(items))
	if f.err != nil {
		return tesla.KeySet{}, f.err
	}
	if f.failFirst > 0 {
		f.failFirst--
		return tesla.KeySet{}, errors.New("temporary API failure")
	}

	out := tesla.KeySet{Keys: map[string][]byte{}, Errors: map[string]string{}}
	seen := make(map[string]bool, len(items))

	for _, item := range items {
		if seen[item.ID] {
			f.sawDuplicateID = true
		}
		seen[item.ID] = true

		if msg, ok := f.reject[item.ID]; ok {
			out.Errors[item.ID] = msg
			continue
		}
		if key, ok := f.keysByWrapped[item.WrappedKey]; ok {
			out.Keys[item.ID] = key
		}
	}

	return out, nil
}

func (f *fakeAPI) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// clip is a generated encrypted clip and the plaintext it should decrypt to.
type clip struct {
	rel   string
	plain []byte
}

func TestExecuteDecryptsEveryClip(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()

	clips := []clip{
		writeClip(t, api, in, "front.mp4", 5000),
		writeClip(t, api, in, "back.mp4", 9000),
		writeClip(t, api, in, filepath.Join("2026-07-30", "left.mp4"), 4096),
		writeClip(t, api, in, filepath.Join("2026-07-30", "right.mp4"), 100),
		writeClip(t, api, in, "sentry.MP4", 12345),
	}

	sum := runPipeline(t, Config{
		InputDir: in, OutputDir: out,
		BatchSize: 2, Workers: 3, SkipExisting: true, Client: api,
	})

	if sum.Decrypted != len(clips) || sum.Failed != 0 {
		t.Fatalf("summary = %+v, want %d decrypted and 0 failed", sum, len(clips))
	}

	for _, c := range clips {
		got, err := os.ReadFile(filepath.Join(out, c.rel))
		if err != nil {
			t.Errorf("read %s: %v", c.rel, err)
			continue
		}
		if string(got) != string(c.plain) {
			t.Errorf("%s: decrypted content does not match", c.rel)
		}
	}

	assertNoLeftovers(t, out)
	assertPrivate(t, out)
}

// TestExecuteSplitsCollidingIDs is the regression test for clips whose headers
// yield the same correlation id: they must never share a key request, or one
// would silently take the other's key.
func TestExecuteSplitsCollidingIDs(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()

	// Identical plaintext size, so identical id, but different keys and content.
	first := writeClip(t, api, in, "a.mp4", 5000)
	second := writeClip(t, api, in, "b.mp4", 5000)

	if idA, idB := clipID(t, in, "a.mp4"), clipID(t, in, "b.mp4"); idA != idB {
		t.Fatalf("test setup: expected colliding ids, got %q and %q", idA, idB)
	}

	sum := runPipeline(t, Config{
		InputDir: in, OutputDir: out,
		BatchSize: 20, Workers: 2, SkipExisting: true, Client: api,
	})

	if api.sawDuplicateID {
		t.Error("two clips with the same id were sent in one request")
	}
	if n := api.requestCount(); n != 2 {
		t.Errorf("made %d key requests, want 2 (one per colliding clip)", n)
	}
	if sum.Decrypted != 2 || sum.Failed != 0 {
		t.Fatalf("summary = %+v, want 2 decrypted and 0 failed", sum)
	}

	for _, c := range []clip{first, second} {
		got, err := os.ReadFile(filepath.Join(out, c.rel))
		if err != nil {
			t.Fatalf("read %s: %v", c.rel, err)
		}
		if string(got) != string(c.plain) {
			t.Errorf("%s: decrypted with the wrong key", c.rel)
		}
	}
}

// TestExecuteReadsEachHeaderOnce guards the batching against the quadratic
// re-reading it used to do: a deferred clip must keep the header it already
// read. Every clip here collides, which is the worst case.
//
// Not parallel: it substitutes the package-level header reader.
func TestExecuteReadsEachHeaderOnce(t *testing.T) {
	const clips = 20

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()

	for i := range clips {
		writeClip(t, api, in, fmt.Sprintf("clip%02d.mp4", i), 5000) // same size → same id
	}

	var (
		mu    sync.Mutex
		reads = map[string]int{}
	)
	original := readHeader
	readHeader = func(path string) (container.Header, error) {
		mu.Lock()
		reads[path]++
		mu.Unlock()
		return original(path)
	}
	t.Cleanup(func() { readHeader = original })

	sum, err := Execute(t.Context(), Config{
		InputDir: in, OutputDir: out, BatchSize: 10, Workers: 4, Client: api,
	}, planJobs(t, in, out), nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if sum.Decrypted != clips {
		t.Fatalf("summary = %+v, want %d decrypted", sum, clips)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reads) != clips {
		t.Fatalf("read %d distinct clips, want %d", len(reads), clips)
	}
	for path, n := range reads {
		if n != 1 {
			t.Errorf("%s was read %d times, want exactly 1", filepath.Base(path), n)
		}
	}
}

func TestExecuteReportsRejectedClips(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()

	writeClip(t, api, in, "ok.mp4", 5000)
	writeClip(t, api, in, "denied.mp4", 6000)
	api.reject = map[string]string{clipID(t, in, "denied.mp4"): "not your clip"}

	var failures []Event
	sum, err := Execute(t.Context(), Config{
		InputDir: in, OutputDir: out, BatchSize: 20, Workers: 2, Client: api,
	}, planJobs(t, in, out), func(ev Event) {
		if ev.Kind == EventFailed {
			failures = append(failures, ev)
		}
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if sum.Decrypted != 1 || sum.Failed != 1 {
		t.Errorf("summary = %+v, want 1 decrypted and 1 failed", sum)
	}
	if len(failures) != 1 || failures[0].Rel != "denied.mp4" {
		t.Fatalf("failures = %+v, want one for denied.mp4", failures)
	}
	if failures[0].Err.Error() != "not your clip" {
		t.Errorf("failure error = %v, want the API message", failures[0].Err)
	}
	assertNoLeftovers(t, out)
}

// TestExecuteSkipsFilesThatAreNotEncrypted covers an ordinary MP4 sitting in the
// input tree: it must be reported as skipped, not as a failure, so it does not
// make the whole run exit non-zero.
func TestExecuteSkipsFilesThatAreNotEncrypted(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()

	writeClip(t, api, in, "encrypted.mp4", 5000)
	if err := os.WriteFile(filepath.Join(in, "already-decrypted.mp4"),
		containertest.MP4(4096, 0x99), 0o600); err != nil {
		t.Fatal(err)
	}

	var events []Event
	sum, err := Execute(t.Context(), Config{
		InputDir: in, OutputDir: out, BatchSize: 20, Workers: 2, Client: api,
	}, planJobs(t, in, out), func(ev Event) { events = append(events, ev) })
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if sum.Decrypted != 1 || sum.Skipped != 1 || sum.Failed != 0 {
		t.Errorf("summary = %+v, want 1 decrypted, 1 skipped, 0 failed", sum)
	}

	idx := slices.IndexFunc(events, func(ev Event) bool { return ev.Kind == EventSkipped })
	if idx < 0 {
		t.Fatalf("no skip event, got %+v", events)
	}
	if !errors.Is(events[idx].Err, container.ErrNotEncrypted) {
		t.Errorf("skip error = %v, want ErrNotEncrypted", events[idx].Err)
	}
}

// TestExecuteFailsTruncatedClips is the regression test for the silent-garbage
// bug: a clip cut short must fail, never be reported as decrypted.
func TestExecuteFailsTruncatedClips(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()

	writeClip(t, api, in, "good.mp4", 5000)

	full := containertest.Clip(t, containertest.MP4(5000, 0x42), containertest.Key(0x42), containertest.WrappedKey(0x42))
	for i, size := range []int{100, 3000, 9000} {
		name := fmt.Sprintf("truncated%d.mp4", i)
		if err := os.WriteFile(filepath.Join(in, name), full[:size], 0o600); err != nil {
			t.Fatal(err)
		}
	}

	sum := runPipeline(t, Config{
		InputDir: in, OutputDir: out, BatchSize: 20, Workers: 2, Client: api,
	})

	if sum.Decrypted != 1 {
		t.Errorf("summary = %+v, want exactly 1 decrypted", sum)
	}
	if sum.Failed+sum.Skipped != 3 {
		t.Errorf("summary = %+v, want the 3 truncated clips reported as failed or skipped", sum)
	}

	for i := range 3 {
		if _, err := os.Stat(filepath.Join(out, fmt.Sprintf("truncated%d.mp4", i))); err == nil {
			t.Errorf("truncated%d.mp4 produced output, it should have failed", i)
		}
	}
	assertNoLeftovers(t, out)
}

func TestExecuteAbortsOnExpiredToken(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()
	writeClip(t, api, in, "a.mp4", 5000)
	writeClip(t, api, in, "b.mp4", 6000)
	api.err = tesla.ErrUnauthorized

	_, err := Execute(t.Context(), Config{
		InputDir: in, OutputDir: out, BatchSize: 1, Workers: 2, Client: api,
	}, planJobs(t, in, out), nil)

	if !errors.Is(err, tesla.ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
	if n := api.requestCount(); n != 1 {
		t.Errorf("made %d requests, want 1: the run should stop at the first 401", n)
	}
}

// TestExecuteContinuesAfterOneFailedBatch checks a transient API failure costs
// only that batch, not the run.
func TestExecuteContinuesAfterOneFailedBatch(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()
	api.failFirst = 1

	for i := range 4 {
		writeClip(t, api, in, fmt.Sprintf("clip%d.mp4", i), 5000+i*1000)
	}

	sum := runPipeline(t, Config{
		InputDir: in, OutputDir: out, BatchSize: 2, Workers: 2, Client: api,
	})

	if sum.Decrypted != 2 || sum.Failed != 2 {
		t.Errorf("summary = %+v, want 2 decrypted and 2 failed", sum)
	}
}

// TestExecuteGivesUpOnRepeatedFailures checks the run stops instead of grinding
// through every batch against a broken endpoint.
func TestExecuteGivesUpOnRepeatedFailures(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()
	api.failFirst = 1000

	for i := range 20 {
		writeClip(t, api, in, fmt.Sprintf("clip%02d.mp4", i), 5000+i*100)
	}

	_, err := Execute(t.Context(), Config{
		InputDir: in, OutputDir: out, BatchSize: 1, Workers: 2, Client: api,
	}, planJobs(t, in, out), nil)
	if err == nil {
		t.Fatal("expected the run to give up")
	}
	if n := api.requestCount(); n != maxConsecutiveBatchFailures {
		t.Errorf("made %d requests, want %d before giving up", n, maxConsecutiveBatchFailures)
	}
}

// TestExecuteCancellation checks a cancelled run leaves no partial output.
func TestExecuteCancellation(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()

	for i := range 12 {
		writeClip(t, api, in, fmt.Sprintf("clip%02d.mp4", i), 200_000+i)
	}

	ctx, cancel := context.WithCancel(t.Context())
	var once sync.Once

	_, err := Execute(ctx, Config{
		InputDir: in, OutputDir: out, BatchSize: 4, Workers: 2, Client: api,
	}, planJobs(t, in, out), func(Event) {
		once.Do(cancel) // Cancel as soon as the first clip lands.
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled or nil", err)
	}

	assertNoLeftovers(t, out)
	for _, path := range decryptedFiles(t, out) {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty: a cancelled run published a partial file", path)
		}
	}
}

func TestExecuteDryRunWritesNothing(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()
	writeClip(t, api, in, "a.mp4", 5000)

	sum := runPipeline(t, Config{
		InputDir: in, OutputDir: out, BatchSize: 20, Workers: 2, DryRun: true, Client: api,
	})

	if sum.Decrypted != 1 {
		t.Errorf("summary = %+v, want 1 decrypted", sum)
	}
	if sum.BytesWritten != 0 {
		t.Errorf("wrote %d bytes in a dry run, want 0", sum.BytesWritten)
	}

	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("dry run created %d entries in the output directory", len(entries))
	}
}

func TestExecuteRemux(t *testing.T) {
	t.Parallel()

	if !HasFFmpeg() {
		t.Skip("ffmpeg is not on PATH")
	}

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()
	writeClip(t, api, in, "a.mp4", 5000)

	// The fixture is not real video, so ffmpeg is expected to reject it; what
	// matters is that the failure is reported and nothing is left behind.
	sum := runPipeline(t, Config{
		InputDir: in, OutputDir: out, BatchSize: 20, Workers: 1, Remux: true, Client: api,
	})

	if sum.Decrypted+sum.Failed != 1 {
		t.Errorf("summary = %+v, want the clip either decrypted or failed", sum)
	}
	assertNoLeftovers(t, out)
}

func TestBuildPlanSkipsExistingAndPreservesLayout(t *testing.T) {
	t.Parallel()

	in, out := t.TempDir(), t.TempDir()
	api := newFakeAPI()

	writeClip(t, api, in, "a.mp4", 5000)
	writeClip(t, api, in, filepath.Join("nested", "b.mp4"), 6000)
	writeClip(t, api, in, "ignored.txt.mp4", 4096)

	// Pretend a.mp4 was decrypted by an earlier run.
	if err := os.WriteFile(filepath.Join(out, "a.mp4"), []byte("done"), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, err := BuildPlan(Config{InputDir: in, OutputDir: out, SkipExisting: true})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}

	if plan.Discovered != 3 {
		t.Errorf("discovered %d clips, want 3", plan.Discovered)
	}
	if len(plan.Skipped) != 1 || plan.Skipped[0] != "a.mp4" {
		t.Errorf("skipped = %v, want [a.mp4]", plan.Skipped)
	}
	if len(plan.Jobs) != 2 {
		t.Fatalf("planned %d jobs, want 2", len(plan.Jobs))
	}

	want := filepath.Join(out, "nested", "b.mp4")
	if !slices.ContainsFunc(plan.Jobs, func(j Job) bool { return j.Dst == want }) {
		t.Errorf("plan does not preserve the nested layout: %+v", plan.Jobs)
	}

	// Without SkipExisting every clip is planned again.
	plan, err = BuildPlan(Config{InputDir: in, OutputDir: out, SkipExisting: false})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Jobs) != 3 || len(plan.Skipped) != 0 {
		t.Errorf("with SkipExisting off: %d jobs and %d skipped, want 3 and 0",
			len(plan.Jobs), len(plan.Skipped))
	}
}

func TestDiscoverIgnoresNonClips(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"a.mp4", "b.MP4", "notes.txt", "event.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	found, err := Discover(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(found) != 2 {
		t.Errorf("found %v, want only the two .mp4 files", found)
	}
}

// TestDiscoverIgnoresSymlinks checks a symlink cannot smuggle an arbitrary file
// into the run, whose header bytes would be sent to the API as a clip id.
func TestDiscoverIgnoresSymlinks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	secret := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(secret, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real.mp4"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "sneaky.mp4")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	found, err := Discover(dir)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(found) != 1 || filepath.Base(found[0]) != "real.mp4" {
		t.Errorf("found %v, want only real.mp4", found)
	}
}

func TestDiscoverMissingDirectory(t *testing.T) {
	t.Parallel()

	if _, err := Discover(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected an error for a missing directory")
	}
}

// --- helpers ---------------------------------------------------------------

func newFakeAPI() *fakeAPI {
	return &fakeAPI{keysByWrapped: map[string][]byte{}, reject: map[string]string{}}
}

func runPipeline(t *testing.T, cfg Config) Summary {
	t.Helper()

	sum, err := Execute(t.Context(), cfg, planJobs(t, cfg.InputDir, cfg.OutputDir), nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return sum
}

func planJobs(t *testing.T, in, out string) []Job {
	t.Helper()

	plan, err := BuildPlan(Config{InputDir: in, OutputDir: out, SkipExisting: true})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	return plan.Jobs
}

// writeClip generates an encrypted clip of the given plaintext size, registers
// its key with the fake API and returns what it should decrypt to.
func writeClip(t *testing.T, api *fakeAPI, dir, rel string, size int) clip {
	t.Helper()

	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	// A key and payload unique to this clip, so a mixed-up key is detectable.
	seed := byte(len(rel)*31 + size)
	key := containertest.Key(seed)
	wrapped := containertest.WrappedKey(seed)
	plain := containertest.MP4(size, seed)

	if err := os.WriteFile(path, containertest.Clip(t, plain, key, wrapped), 0o600); err != nil {
		t.Fatal(err)
	}

	api.mu.Lock()
	api.keysByWrapped[base64.StdEncoding.EncodeToString(wrapped)] = key
	api.mu.Unlock()

	return clip{rel: rel, plain: plain}
}

// clipID returns the correlation id the pipeline will read from a clip.
func clipID(t *testing.T, dir, rel string) string {
	t.Helper()

	header, err := readHeaderFromDisk(filepath.Join(dir, rel))
	if err != nil {
		t.Fatalf("read header of %s: %v", rel, err)
	}
	return header.ID
}

// decryptedFiles lists the .mp4 files produced under dir.
func decryptedFiles(t *testing.T, dir string) []string {
	t.Helper()

	var found []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".mp4" {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// assertNoLeftovers checks no temporary file survived the run.
func assertNoLeftovers(t *testing.T, dir string) {
	t.Helper()

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasPrefix(filepath.Base(path), ".tesdecrypt-") {
			t.Errorf("temporary file left behind: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// assertPrivate checks decrypted footage is not readable by other users.
func assertPrivate(t *testing.T, dir string) {
	t.Helper()

	for _, path := range decryptedFiles(t, dir) {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			t.Errorf("%s has mode %o, want no group or world access", path, mode)
		}
	}
}
