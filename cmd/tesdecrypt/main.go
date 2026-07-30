// Command tesdecrypt batch-decrypts the encrypted dashcam clips Tesla writes to
// USB from firmware 2026.20 onwards.
//
// It reproduces what the official viewer at dashcam.tesla.com does in the
// browser: read each clip's header, ask Tesla for that clip's key, and decrypt
// locally. Video bytes never leave the machine.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"

	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/pipeline"
	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/tesla"
	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/ui"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

// tokenEnv is the environment variable read when --token is not given.
const tokenEnv = "TESLA_TOKEN"

// apiBaseEnv overrides the API origin. Only useful for testing against a stub.
const apiBaseEnv = "TESLA_API_BASE"

// defaultBatchSize is how many clips share one key request.
const defaultBatchSize = 20

func main() {
	if err := fang.Execute(
		context.Background(),
		newRootCmd(),
		fang.WithVersion(version),
	); err != nil {
		os.Exit(1)
	}
}

// options holds the parsed command line.
type options struct {
	inputDir  string
	outputDir string

	token        string
	batchSize    int
	workers      int
	skipExisting bool
	dryRun       bool
	remux        bool
	plain        bool
}

func newRootCmd() *cobra.Command {
	var opts options

	cmd := &cobra.Command{
		Use:   "tesdecrypt <input-dir> <output-dir>",
		Short: "Batch-decrypt Tesla 2026.20+ encrypted dashcam clips",
		Long: `Batch-decrypt Tesla 2026.20+ encrypted dashcam clips.

Tesla encrypts dashcam and Sentry Mode recordings on the USB drive from firmware
2026.20 onwards. The official viewer decrypts them one at a time in the browser;
this decrypts a whole drive at once.

Only each clip's identifier and the ownership metadata already in its header are
sent to Tesla to retrieve the per-file key. The video itself is decrypted
locally and never uploaded.

Getting a token:
  1. Open https://dashcam.tesla.com and sign in.
  2. Open DevTools and select the Network tab.
  3. Drop any encrypted clip onto the page.
  4. Open any /api/1/ request and copy the value after "Authorization: Bearer ".

Tokens expire, so grab a fresh one each session. Prefer the ` + tokenEnv + `
environment variable over --token to keep it out of your shell history.`,
		Example: `  # Decrypt a whole drive
  export TESLA_TOKEN="..."
  tesdecrypt /run/media/$USER/TESLA/TeslaCam ~/Videos/TeslaCam

  # Check what would happen, without writing anything
  tesdecrypt --dry-run /run/media/$USER/TESLA/TeslaCam ~/Videos/TeslaCam

  # Remux through ffmpeg for players that dislike Tesla's container
  tesdecrypt --remux /run/media/$USER/TESLA/TeslaCam ~/Videos/TeslaCam`,
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.inputDir, opts.outputDir = args[0], args[1]
			return run(cmd.Context(), opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.token, "token", "", "Tesla bearer token (default: $"+tokenEnv+")")
	f.IntVar(&opts.batchSize, "batch-size", defaultBatchSize, "clips per key request")
	f.IntVarP(&opts.workers, "workers", "j", runtime.NumCPU(), "clips decrypted in parallel")
	f.BoolVar(&opts.skipExisting, "skip-existing", true, "skip clips already in the output directory")
	f.BoolVar(&opts.dryRun, "dry-run", false, "fetch keys but write nothing")
	f.BoolVar(&opts.remux, "remux", false, "losslessly remux each clip with ffmpeg")
	f.BoolVar(&opts.plain, "plain", false, "plain line-by-line output, no progress bar")

	return cmd
}

func run(ctx context.Context, opts options) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	token := opts.token
	if token == "" {
		token = os.Getenv(tokenEnv)
	}
	if token == "" {
		return fmt.Errorf("no token: pass --token or set %s (run with --help for how to get one)", tokenEnv)
	}

	if _, err := os.Stat(opts.inputDir); err != nil {
		return fmt.Errorf("input directory: %w", err)
	}
	if opts.remux && !pipeline.HasFFmpeg() {
		return errors.New("--remux needs ffmpeg on PATH")
	}

	clientOpts, err := apiBaseOverride()
	if err != nil {
		return err
	}

	cfg := pipeline.Config{
		InputDir:     opts.inputDir,
		OutputDir:    opts.outputDir,
		BatchSize:    opts.batchSize,
		Workers:      opts.workers,
		SkipExisting: opts.skipExisting,
		DryRun:       opts.dryRun,
		Remux:        opts.remux,
		Client:       tesla.New(token, clientOpts...),
	}

	styles := ui.DefaultStyles()
	out := os.Stdout

	plan, err := pipeline.BuildPlan(cfg)
	if err != nil {
		return err
	}
	ui.Header(out, styles, opts.inputDir, plan)

	if len(plan.Jobs) == 0 {
		ui.Note(out, styles, "Nothing to do.")
		return nil
	}
	if opts.dryRun {
		ui.Note(out, styles, "Dry run: keys will be fetched but no file is written.")
	}
	ui.Note(out, styles, "")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	reporter := ui.New(out, opts.plain, cancel)
	reporter.Start(len(plan.Jobs))

	sum, runErr := pipeline.Execute(ctx, cfg, plan.Jobs, reporter.Emit)
	reporter.Finish(sum, opts.outputDir)

	return exitStatus(sum, runErr)
}

// apiBaseOverride reads TESLA_API_BASE, which points the client at a stub
// server during testing.
//
// It is validated rather than trusted: the bearer token travels on every
// request, so an origin picked up from the environment must at least be HTTPS,
// and any override is announced so it cannot redirect the token quietly.
func apiBaseOverride() ([]tesla.Option, error) {
	base := os.Getenv(apiBaseEnv)
	if base == "" {
		return nil, nil
	}

	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", apiBaseEnv, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%s: %q has no host", apiBaseEnv, base)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s: credentials in the URL are not allowed", apiBaseEnv)
	}
	if u.Scheme != "https" && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("%s: %q must use https (http is only allowed on localhost)", apiBaseEnv, base)
	}

	_, _ = fmt.Fprintf(os.Stderr, "warning: sending your token to %s instead of %s\n", u.Redacted(), tesla.DefaultBaseURL)

	return []tesla.Option{tesla.WithBaseURL(strings.TrimSuffix(base, "/"))}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// exitStatus turns the run's outcome into the error the command exits with.
func exitStatus(sum pipeline.Summary, runErr error) error {
	switch {
	case errors.Is(runErr, tesla.ErrUnauthorized):
		return errors.New("token expired or invalid: get a fresh one from dashcam.tesla.com")
	case errors.Is(runErr, context.Canceled):
		return errors.New("cancelled")
	case runErr != nil:
		return runErr
	case sum.Failed > 0:
		return fmt.Errorf("%d clip(s) failed", sum.Failed)
	default:
		return nil
	}
}
