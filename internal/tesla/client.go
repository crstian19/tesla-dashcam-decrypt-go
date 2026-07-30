// Package tesla talks to the key endpoint behind dashcam.tesla.com.
//
// Only file identifiers and the ownership metadata already present in each
// clip's header are sent. Video bytes never leave the machine.
package tesla

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultBaseURL is the origin serving the browser viewer and its API.
const DefaultBaseURL = "https://dashcam.tesla.com"

const batchPath = "/api/1/decrypt/batch"

// maxErrorBody caps how much of an error response is kept for the message.
const maxErrorBody = 512

// maxResponseBody caps a successful response. A batch of 20 keys is a couple of
// kilobytes; without a cap, a hostile endpoint could answer 200 OK with an
// endless body, which the transport would happily gunzip until memory ran out.
const maxResponseBody = 4 << 20

var (
	// ErrUnauthorized means the token was rejected; it has most likely expired.
	ErrUnauthorized = errors.New("token expired or invalid")
	// ErrEmptyToken means no bearer token was supplied.
	ErrEmptyToken = errors.New("empty bearer token")
	// ErrResponseTooLarge means the endpoint sent more than maxResponseBody.
	ErrResponseTooLarge = errors.New("response is implausibly large")
)

// Item is one file in a key request. ID only correlates the result with the
// request: the key itself is unwrapped from WrappedKey, so ids need only be
// unique within a single request. See package container.
type Item struct {
	ID         string `json:"id"`
	VIN        string `json:"vin,omitempty"`
	KeyID      uint32 `json:"key_id,omitempty"`
	Timestamp  uint64 `json:"timestamp,omitempty"`
	WrappedKey string `json:"wrapped_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
}

// Client fetches per-file decryption keys.
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
	maxRetries int
	backoff    time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the API origin. Used by tests.
func WithBaseURL(u string) Option {
	return func(cl *Client) { cl.baseURL = u }
}

// WithRetries sets how many times a throttled or failing request is retried and
// the base delay for the exponential backoff.
func WithRetries(n int, base time.Duration) Option {
	return func(cl *Client) {
		cl.maxRetries = max(0, n)
		cl.backoff = base
	}
}

// New returns a Client authenticating with the given bearer token.
func New(token string, opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    DefaultBaseURL,
		token:      token,
		maxRetries: 3,
		backoff:    time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type batchRequest struct {
	Items []Item `json:"items"`
}

type batchResponse struct {
	Results []struct {
		ID    string `json:"id"`
		Key   string `json:"key"`
		Error string `json:"error"`
	} `json:"results"`
}

// KeySet is the outcome of one key request: the keys that were granted and,
// per file, any error the API reported for it.
type KeySet struct {
	Keys   map[string][]byte
	Errors map[string]string
}

// FetchKeys requests the decryption keys for items. A per-file rejection is
// reported in the returned KeySet; only transport and auth failures return an
// error.
func (c *Client) FetchKeys(ctx context.Context, items []Item) (KeySet, error) {
	out := KeySet{Keys: make(map[string][]byte, len(items)), Errors: make(map[string]string)}
	if len(items) == 0 {
		return out, nil
	}
	if c.token == "" {
		return KeySet{}, ErrEmptyToken
	}

	body, err := json.Marshal(batchRequest{Items: items})
	if err != nil {
		return KeySet{}, fmt.Errorf("encode request: %w", err)
	}

	raw, err := c.postWithRetries(ctx, body)
	if err != nil {
		return KeySet{}, err
	}

	var parsed batchResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return KeySet{}, fmt.Errorf("decode response: %w", err)
	}

	for _, r := range parsed.Results {
		if r.Error != "" {
			out.Errors[r.ID] = r.Error
			continue
		}
		key, err := base64.StdEncoding.DecodeString(r.Key)
		if err != nil {
			out.Errors[r.ID] = fmt.Sprintf("malformed key in response: %v", err)
			continue
		}
		out.Keys[r.ID] = key
	}

	return out, nil
}

// postWithRetries posts body to the batch endpoint, retrying throttling and
// server errors with exponential backoff.
func (c *Client) postWithRetries(ctx context.Context, body []byte) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := c.backoff << (attempt - 1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		raw, retryable, err := c.post(ctx, body)
		if err == nil {
			return raw, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
	}

	return nil, fmt.Errorf("after %d retries: %w", c.maxRetries, lastErr)
}

// post performs a single request and reports whether a failure is worth retrying.
func (c *Client) post(ctx context.Context, body []byte) (raw []byte, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+batchPath, bytes.NewReader(body))
	if err != nil {
		return nil, false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", c.baseURL)
	req.Header.Set("Referer", c.baseURL+"/")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Transport failures are worth another attempt unless we are shutting down.
		return nil, ctx.Err() == nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Nothing useful to do with a close error on a response body.

	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return nil, false, ErrUnauthorized
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return nil, true, statusError(resp)
	case resp.StatusCode != http.StatusOK:
		return nil, false, statusError(resp)
	}

	// Read one byte past the cap so an oversized body is detectable.
	raw, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return nil, true, fmt.Errorf("read response: %w", err)
	}
	if len(raw) > maxResponseBody {
		return nil, false, fmt.Errorf("%w: over %d bytes", ErrResponseTooLarge, maxResponseBody)
	}
	return raw, false, nil
}

// statusError builds an error carrying the status and a snippet of the body.
func statusError(resp *http.Response) error {
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	if len(snippet) == 0 {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return fmt.Errorf("unexpected status %s: %s", resp.Status, bytes.TrimSpace(snippet))
}
