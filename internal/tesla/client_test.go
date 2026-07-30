package tesla

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetchKeysReturnsKeys(t *testing.T) {
	t.Parallel()

	var got batchRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != batchPath {
			t.Errorf("path = %s, want %s", r.URL.Path, batchPath)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer token-123" {
			t.Errorf("Authorization = %q, want %q", auth, "Bearer token-123")
		}

		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("decode request: %v", err)
		}

		writeJSON(t, w, `{"results":[
			{"id":"aaa","key":"`+base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))+`"},
			{"id":"bbb","key":"`+base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))+`"}
		]}`)
	}))
	defer srv.Close()

	client := New("token-123", WithBaseURL(srv.URL))
	keys, err := client.FetchKeys(t.Context(), []Item{
		{ID: "aaa", VIN: "5YJ3E1EA7KF000001", KeyID: 1, Timestamp: 42, WrappedKey: "d3JhcA==", PublicKey: "cHVi"},
		{ID: "bbb"},
	})
	if err != nil {
		t.Fatalf("FetchKeys: %v", err)
	}

	if len(keys.Keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys.Keys))
	}
	if string(keys.Keys["aaa"]) != "0123456789abcdef" {
		t.Errorf("key aaa = %q", keys.Keys["aaa"])
	}

	// Empty metadata fields are omitted from the request rather than sent as
	// zero values.
	if len(got.Items) != 2 {
		t.Fatalf("sent %d items, want 2", len(got.Items))
	}
	if got.Items[0].VIN != "5YJ3E1EA7KF000001" {
		t.Errorf("first item VIN = %q", got.Items[0].VIN)
	}
	if got.Items[1].VIN != "" || got.Items[1].KeyID != 0 {
		t.Errorf("second item should carry the id alone, got %+v", got.Items[1])
	}
}

func TestFetchKeysReportsPerFileErrors(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, `{"results":[
			{"id":"ok","key":"`+base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))+`"},
			{"id":"nope","error":"clip not owned by this account"},
			{"id":"bad","key":"not base64!"}
		]}`)
	}))
	defer srv.Close()

	keys, err := New("t", WithBaseURL(srv.URL)).FetchKeys(t.Context(),
		[]Item{{ID: "ok"}, {ID: "nope"}, {ID: "bad"}})
	if err != nil {
		t.Fatalf("FetchKeys: %v", err)
	}

	if len(keys.Keys) != 1 {
		t.Errorf("got %d keys, want 1", len(keys.Keys))
	}
	if keys.Errors["nope"] != "clip not owned by this account" {
		t.Errorf("error for nope = %q", keys.Errors["nope"])
	}
	if keys.Errors["bad"] == "" {
		t.Error("a malformed key should be reported as a per-file error")
	}
}

func TestFetchKeysUnauthorized(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))

		_, err := New("t", WithBaseURL(srv.URL)).FetchKeys(t.Context(), []Item{{ID: "x"}})
		if !errors.Is(err, ErrUnauthorized) {
			t.Errorf("status %d: error = %v, want ErrUnauthorized", status, err)
		}
		srv.Close()
	}
}

func TestFetchKeysRetriesTransientFailures(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch attempts.Add(1) {
		case 1:
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		default:
			writeJSON(t, w, `{"results":[{"id":"x","key":"`+
				base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))+`"}]}`)
		}
	}))
	defer srv.Close()

	client := New("t", WithBaseURL(srv.URL), WithRetries(3, time.Millisecond))
	keys, err := client.FetchKeys(t.Context(), []Item{{ID: "x"}})
	if err != nil {
		t.Fatalf("FetchKeys: %v", err)
	}
	if len(keys.Keys) != 1 {
		t.Errorf("got %d keys, want 1", len(keys.Keys))
	}
	if n := attempts.Load(); n != 3 {
		t.Errorf("made %d attempts, want 3", n)
	}
}

func TestFetchKeysGivesUpAfterRetries(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := New("t", WithBaseURL(srv.URL), WithRetries(2, time.Millisecond))
	if _, err := client.FetchKeys(t.Context(), []Item{{ID: "x"}}); err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	if n := attempts.Load(); n != 3 {
		t.Errorf("made %d attempts, want 3 (initial + 2 retries)", n)
	}
}

func TestFetchKeysDoesNotRetryClientErrors(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	client := New("t", WithBaseURL(srv.URL), WithRetries(3, time.Millisecond))
	if _, err := client.FetchKeys(t.Context(), []Item{{ID: "x"}}); err == nil {
		t.Fatal("expected an error")
	}
	if n := attempts.Load(); n != 1 {
		t.Errorf("made %d attempts, want 1", n)
	}
}

// TestFetchKeysRejectsHugeResponse checks a hostile endpoint cannot exhaust
// memory by answering 200 OK with an endless body.
func TestFetchKeysRejectsHugeResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		chunk := bytes.Repeat([]byte("A"), 64<<10)
		for written := 0; written <= maxResponseBody; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return // The client hung up, which is the point of the test.
			}
		}
	}))
	defer srv.Close()

	client := New("t", WithBaseURL(srv.URL), WithRetries(0, time.Millisecond))
	_, err := client.FetchKeys(t.Context(), []Item{{ID: "x"}})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
}

func TestFetchKeysEdgeCases(t *testing.T) {
	t.Parallel()

	client := New("", WithBaseURL("http://127.0.0.1:0"))

	keys, err := client.FetchKeys(t.Context(), nil)
	if err != nil {
		t.Errorf("no items should be a no-op, got %v", err)
	}
	if len(keys.Keys) != 0 {
		t.Errorf("got %d keys, want none", len(keys.Keys))
	}

	if _, err := client.FetchKeys(t.Context(), []Item{{ID: "x"}}); !errors.Is(err, ErrEmptyToken) {
		t.Errorf("error = %v, want ErrEmptyToken", err)
	}
}

func TestFetchKeysHonoursContext(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	client := New("t", WithBaseURL(srv.URL), WithRetries(5, time.Hour))
	if _, err := client.FetchKeys(ctx, []Item{{ID: "x"}}); err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if _, err := io.WriteString(w, body); err != nil {
		t.Errorf("write response: %v", err)
	}
}
