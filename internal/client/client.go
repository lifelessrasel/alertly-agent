// Package client talks to the Alertly agent API.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// StatusError is returned when the API answers with an unexpected status code.
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("unexpected status %d: %s", e.Status, e.Body)
}

// Client sends authenticated JSON requests to the API.
type Client struct {
	endpoint  string
	token     string
	userAgent string
	http      *http.Client
}

// New creates a client for an endpoint such as https://alertly.net/api/v1.
func New(endpoint, token, version string) *Client {
	return &Client{
		endpoint:  endpoint,
		token:     token,
		userAgent: "alertly-agent/" + version,
		http:      &http.Client{Timeout: 30 * time.Second},
	}
}

// Post sends body as JSON to /agent/{path} and decodes a JSON reply into out, when out is not nil.
func (c *Client) Post(ctx context.Context, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	return c.send(ctx, http.MethodPost, path, bytes.NewReader(payload), out)
}

// Get requests /agent/{path} and decodes the JSON reply into out.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.send(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) send(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+"/agent/"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &StatusError{Status: resp.StatusCode, Body: string(snippet)}
	}

	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	return json.NewDecoder(resp.Body).Decode(out)
}
