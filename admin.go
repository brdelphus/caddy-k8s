package k8singress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// upsertRoute checks if a route with the given @id exists and either updates
// it (PUT /id/<id>) or appends it to the server's route list (POST /config/…).
func (c *adminClient) upsertRoute(ctx context.Context, serverName string, r caddyRoute) error {
	exists, err := c.routeExists(ctx, r.ID)
	if err != nil {
		return err
	}

	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal route: %w", err)
	}

	if exists {
		return c.do(ctx, http.MethodPut, "/id/"+r.ID, body)
	}
	return c.do(ctx, http.MethodPost,
		fmt.Sprintf("/config/apps/http/servers/%s/routes/", serverName),
		body,
	)
}

// deleteRoute removes a route by its @id. Returns nil if the route doesn't exist.
func (c *adminClient) deleteRoute(ctx context.Context, id string) error {
	exists, err := c.routeExists(ctx, id)
	if err != nil || !exists {
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
