package k8singress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// adminClient is a minimal Caddy admin API client.
type adminClient struct {
	base string // e.g. "localhost:2019"
	http *http.Client
}

func newAdminClient(addr string) *adminClient {
	return &adminClient{
		base: "http://" + addr,
		http: &http.Client{},
	}
}

// upsertRoute checks if a route with the given @id exists in Caddy's live
// config. If it does and its content is already identical to r, it returns
// immediately (no-op) — this breaks the infinite-reload loop that would
// otherwise occur because every admin API mutation triggers a Caddy config
// reload which restarts k8s_ingress, which would sync again, mutate again, etc.
// If the route is absent or stale, it uses DELETE+POST (avoiding Caddy's PUT
// duplicate-@id bug). Retries up to 3 times with backoff.
func (c *adminClient) upsertRoute(ctx context.Context, serverName string, r caddyRoute) error {
	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal route: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}

		current, err := c.getRoute(ctx, r.ID)
		if err != nil {
			lastErr = err
			continue
		}

		if current != nil {
			// Normalise both sides to comparable JSON so field-ordering differences
			// between our marshaller and Caddy's don't trigger spurious updates.
			currentNorm, err1 := normaliseJSON(current)
			desiredNorm, err2 := normaliseJSON(body)
			if err1 == nil && err2 == nil && currentNorm == desiredNorm {
				return nil // already up-to-date, no mutation needed
			}
			// Route exists but content differs — replace it.
			// PUT /id/<id> fails when the body carries @id: Caddy momentarily indexes
			// both the old and new entries before removing the old one, triggering a
			// duplicate-@id validation error. Delete then re-post instead.
			if err := c.do(ctx, http.MethodDelete, "/id/"+r.ID, nil); err != nil {
				lastErr = fmt.Errorf("delete before update: %w", err)
				continue
			}
		}

		err = c.do(ctx, http.MethodPost,
			fmt.Sprintf("/config/apps/http/servers/%s/routes/", serverName),
			body,
		)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

// getRoute fetches the current route JSON for the given @id. Returns nil, nil
// if the route does not exist.
func (c *adminClient) getRoute(ctx context.Context, id string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/id/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /id/%s: status %d", id, resp.StatusCode)
	}
	return b, nil
}

// normaliseJSON round-trips JSON through interface{} so the output has
// consistent key ordering (Go's map iteration is random, but json.Marshal
// sorts map keys alphabetically since Go 1.12 via reflect).
func normaliseJSON(b []byte) (string, error) {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	out, err := json.Marshal(v)
	return string(out), err
}

// deleteRoute removes a route by its @id. Returns nil if the route doesn't exist.
func (c *adminClient) deleteRoute(ctx context.Context, id string) error {
	b, err := c.getRoute(ctx, id)
	if err != nil || b == nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, "/id/"+id, nil)
}

// routeExists returns true if a route with the given @id is present in the
// current Caddy config.
func (c *adminClient) routeExists(ctx context.Context, id string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/id/"+id, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK, nil
}

// resolveServerName returns the name of the Caddy HTTP server that listens on
// the given port (e.g. ":443" or ":80"). If hint is non-empty it is returned
// directly, allowing explicit override via config.
func resolveServerName(ctx context.Context, c *adminClient, hint, port string) (string, error) {
	if hint != "" {
		return hint, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/config/apps/http/servers", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET /config/apps/http/servers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET /config/apps/http/servers: status %d", resp.StatusCode)
	}

	var servers map[string]struct {
		Listen []string `json:"listen"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		return "", fmt.Errorf("decode servers: %w", err)
	}

	for name, srv := range servers {
		for _, addr := range srv.Listen {
			if strings.HasSuffix(addr, port) {
				return name, nil
			}
		}
	}

	return "", fmt.Errorf("no Caddy server listening on %s found — set server_name explicitly", port)
}

func (c *adminClient) do(ctx context.Context, method, path string, body []byte) error {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, respBody)
	}
	return nil
}

// upsertTLSPolicy creates or updates a TLS automation policy identified by its
// @id field. Uses PUT /id/<id> if the policy already exists, POST to the
// policies array otherwise.
func (c *adminClient) upsertTLSPolicy(ctx context.Context, p tlsAutomationPolicy) error {
	exists, err := c.routeExists(ctx, p.ID)
	if err != nil {
		return err
	}
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal tls policy: %w", err)
	}
	if exists {
		return c.do(ctx, http.MethodPut, "/id/"+p.ID, body)
	}
	return c.do(ctx, http.MethodPost, "/config/apps/tls/automation/policies/", body)
}

// deleteTLSPolicy removes a TLS automation policy by its @id.
// Returns nil if the policy does not exist.
func (c *adminClient) deleteTLSPolicy(ctx context.Context, id string) error {
	exists, err := c.routeExists(ctx, id)
	if err != nil || !exists {
		return err
	}
	return c.do(ctx, http.MethodDelete, "/id/"+id, nil)
}

// postJSON sends a JSON payload to the given path via POST.
func (c *adminClient) postJSON(ctx context.Context, path string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	return c.do(ctx, http.MethodPost, path, body)
}
