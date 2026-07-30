package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/pipeline"
	"github.com/crstian19/tesla-dashcam-decrypt-go/internal/tesla"
)

func TestExitStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sum     pipeline.Summary
		runErr  error
		wantErr bool
		wantMsg string
	}{
		{
			name: "everything decrypted",
			sum:  pipeline.Summary{Decrypted: 10},
		},
		{
			name: "clips that were not encrypted do not fail the run",
			sum:  pipeline.Summary{Decrypted: 8, Skipped: 2},
		},
		{
			name:    "failed clips fail the run",
			sum:     pipeline.Summary{Decrypted: 8, Failed: 2},
			wantErr: true,
			wantMsg: "2 clip(s) failed",
		},
		{
			name:    "an expired token explains itself",
			runErr:  tesla.ErrUnauthorized,
			wantErr: true,
			wantMsg: "dashcam.tesla.com",
		},
		{
			name:    "cancellation is not a crash",
			runErr:  context.Canceled,
			wantErr: true,
			wantMsg: "cancelled",
		},
		{
			name:    "any other error is passed through",
			runErr:  errors.New("disk full"),
			wantErr: true,
			wantMsg: "disk full",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := exitStatus(tc.sum, tc.runErr)
			if tc.wantErr != (err != nil) {
				t.Fatalf("error = %v, want error: %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantMsg)
			}
		})
	}
}

// TestAPIBaseOverride checks the token cannot be redirected to an arbitrary
// origin, or sent in the clear, by an environment variable.
func TestAPIBaseOverride(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr string
		wantSet bool
	}{
		{name: "unset uses the default origin", value: ""},
		{name: "https is accepted", value: "https://dashcam.tesla.com", wantSet: true},
		{name: "http on loopback is accepted for testing", value: "http://127.0.0.1:8080", wantSet: true},
		{name: "http on localhost is accepted", value: "http://localhost:8080", wantSet: true},
		{name: "plain http elsewhere is refused", value: "http://evil.example", wantErr: "must use https"},
		{name: "credentials in the URL are refused", value: "https://dashcam.tesla.com@evil.example", wantErr: "credentials"},
		{name: "a URL with no host is refused", value: "https://", wantErr: "no host"},
		{name: "garbage is refused", value: "://nope", wantErr: "TESLA_API_BASE"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(apiBaseEnv, tc.value)

			opts, err := apiBaseOverride()
			switch {
			case tc.wantErr != "":
				if err == nil {
					t.Fatalf("value %q was accepted, want an error", tc.value)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
				}
			case err != nil:
				t.Fatalf("value %q was refused: %v", tc.value, err)
			case tc.wantSet != (len(opts) > 0):
				t.Errorf("got %d options, want set: %v", len(opts), tc.wantSet)
			}
		})
	}
}

func TestIsLoopback(t *testing.T) {
	t.Parallel()

	loopback := []string{"localhost", "127.0.0.1", "127.1.2.3", "::1"}
	for _, host := range loopback {
		if !isLoopback(host) {
			t.Errorf("isLoopback(%q) = false, want true", host)
		}
	}

	remote := []string{"dashcam.tesla.com", "8.8.8.8", "evil.example", ""}
	for _, host := range remote {
		if isLoopback(host) {
			t.Errorf("isLoopback(%q) = true, want false", host)
		}
	}
}

// TestRootCommandFlags guards the flag surface the README documents.
func TestRootCommandFlags(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()

	for _, name := range []string{"token", "batch-size", "workers", "skip-existing", "dry-run", "remux", "plain"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is missing", name)
		}
	}
	if cmd.Flags().ShorthandLookup("j") == nil {
		t.Error("shorthand -j for --workers is missing")
	}

	// The token must never be shown as a default, or --help would print it.
	if def := cmd.Flags().Lookup("token").DefValue; def != "" {
		t.Errorf("--token default = %q, want it empty so the token never reaches --help", def)
	}

	if err := cmd.Args(cmd, []string{"only-one"}); err == nil {
		t.Error("the command should require both an input and an output directory")
	}
}
