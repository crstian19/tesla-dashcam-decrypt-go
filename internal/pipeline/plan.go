// Package pipeline discovers encrypted clips, fetches their keys in batches and
// decrypts them concurrently.
package pipeline

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Job is one clip to decrypt.
type Job struct {
	// Src is the encrypted clip on the input drive.
	Src string
	// Dst is where the decrypted MP4 will be written.
	Dst string
	// Rel is Src relative to the input directory, used for display.
	Rel string
}

// Plan is the work Execute will do.
type Plan struct {
	Jobs []Job
	// Discovered is how many clips were found before filtering.
	Discovered int
	// Skipped lists clips already present in the output directory.
	Skipped []string
}

// Discover walks root and returns every .mp4 file, sorted. Tesla keeps the .mp4
// extension for encrypted clips. Unreadable entries are skipped rather than
// aborting the walk.
//
// Only regular files are returned. A symlink in the input tree would otherwise
// be followed and its target's header bytes sent to the API as a clip id, and a
// FIFO or device node would block the scan indefinitely.
func Discover(root string) ([]string, error) {
	var found []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".mp4") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", root, err)
	}

	slices.Sort(found)
	return found, nil
}

// BuildPlan discovers clips under cfg.InputDir and maps them to output paths,
// preserving the directory layout of the drive.
func BuildPlan(cfg Config) (Plan, error) {
	files, err := Discover(cfg.InputDir)
	if err != nil {
		return Plan{}, err
	}

	plan := Plan{Discovered: len(files)}
	for _, src := range files {
		rel, err := filepath.Rel(cfg.InputDir, src)
		if err != nil {
			return Plan{}, fmt.Errorf("relative path for %s: %w", src, err)
		}

		dst := filepath.Join(cfg.OutputDir, rel)
		if cfg.SkipExisting {
			if _, err := os.Stat(dst); err == nil {
				plan.Skipped = append(plan.Skipped, rel)
				continue
			}
		}

		plan.Jobs = append(plan.Jobs, Job{Src: src, Dst: dst, Rel: rel})
	}

	return plan, nil
}
