package k8singress

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// accessLogManager enables server-level access logging and manages the
// skip_hosts list for per-Ingress opt-out.
//
// When access logging is enabled, the manager:
//  1. Creates a named "access" logger in Caddy's logging config (stderr, JSON).
//  2. Sets logs.default_logger_name on the HTTPS server to "access".
//  3. Maintains a skip_hosts list so individual Ingresses can suppress logging.
type accessLogManager struct {
	mu             sync.Mutex
	serverName     string // HTTPS server (srv0)
	httpServerName string // HTTP server (srv1)
	adminAPI       string
	logger         *zap.Logger
	// disabled maps ingress key (namespace/name) to the hosts it contributes
	// to skip_hosts.
	disabled map[string][]string
	// lastSkip is the sorted skip_hosts slice sent in the last successful
	// rebuild(). Used to skip no-op PATCHes that would trigger Caddy's
	// "config is unchanged" log noise.
	lastSkip string // JSON-encoded for easy comparison
}

func newAccessLogManager(serverName, httpServerName, adminAPI string, logger *zap.Logger) *accessLogManager {
	return &accessLogManager{
		serverName:     serverName,
		httpServerName: httpServerName,
		adminAPI:       adminAPI,
		logger:         logger,
		disabled:       make(map[string][]string),
	}
}

// Enable registers the "access" logger in Caddy's logging config and sets it
// as the default access log for the HTTP server. Called once during Start().
func (m *accessLogManager) Enable(ctx context.Context) error {
	adm := newAdminClient(m.adminAPI)

	// Register a named "access" logger that captures only HTTP access entries.
	// The include filter is required: without it, both this logger AND Caddy's
	// default global logger write the same http.log.access.* entries, producing
	// duplicates. The default logger is told to exclude the same namespace below.
	loggerPayload := map[string]interface{}{
		"writer":  map[string]interface{}{"output": "stderr"},
		"encoder": map[string]interface{}{"format": "json"},
		"include": []string{"http.log.access"},
	}
	body, err := json.Marshal(loggerPayload)
	if err != nil {
		return fmt.Errorf("marshal access logger: %w", err)
	}
	if err := adm.putOrPatch(ctx, "/config/logging/logs/access", body); err != nil {
		return fmt.Errorf("configure access logger: %w", err)
	}

	// Tell the default global logger to skip http.log.access entries so they
	// are not written a second time by the catch-all default logger.
	defaultExclPayload := map[string]interface{}{
		"exclude": []string{"http.log.access"},
	}
	body, err = json.Marshal(defaultExclPayload)
	if err != nil {
		return fmt.Errorf("marshal default logger exclude: %w", err)
	}
	if err := adm.putOrPatch(ctx, "/config/logging/logs/default", body); err != nil {
		return fmt.Errorf("configure default logger exclude: %w", err)
	}

	// Point both HTTP and HTTPS servers at the "access" logger.
	// Initialize skip_hosts as an empty array so rebuild() can always use
	// PATCH (update) rather than PUT (create), avoiding 409 on the second call.
	logsPayload := map[string]interface{}{
		"default_logger_name": "access",
		"skip_hosts":          []string{},
	}
	body, err = json.Marshal(logsPayload)
	if err != nil {
		return fmt.Errorf("marshal server logs config: %w", err)
	}
	for _, srv := range m.servers() {
		if err := adm.putOrPatch(ctx,
			fmt.Sprintf("/config/apps/http/servers/%s/logs", srv), body); err != nil {
			return fmt.Errorf("configure server logs (%s): %w", srv, err)
		}
	}

	m.logger.Info("k8s_ingress: access logging enabled",
		zap.String("https_server", m.serverName),
		zap.String("http_server", m.httpServerName))
	return nil
}

// servers returns the server names to manage, omitting empty names.
func (m *accessLogManager) servers() []string {
	s := []string{m.serverName}
	if m.httpServerName != "" && m.httpServerName != m.serverName {
		s = append(s, m.httpServerName)
	}
	return s
}

// Skip adds the given hosts to the skip_hosts list for this Ingress, suppressing
// access logs for requests to those hosts.
func (m *accessLogManager) Skip(ctx context.Context, ingKey string, hosts []string) error {
	m.mu.Lock()
	m.disabled[ingKey] = hosts
	m.mu.Unlock()
	return m.rebuild(ctx)
}

// Unskip removes the Ingress from the skip list, re-enabling access logging
// for its hosts.
func (m *accessLogManager) Unskip(ctx context.Context, ingKey string) error {
	m.mu.Lock()
	delete(m.disabled, ingKey)
	m.mu.Unlock()
	return m.rebuild(ctx)
}

// rebuild collects all disabled hosts and PUTs the skip_hosts array to Caddy.
func (m *accessLogManager) rebuild(ctx context.Context) error {
	m.mu.Lock()
	seen := make(map[string]bool)
	var skip []string
	for _, hosts := range m.disabled {
		for _, h := range hosts {
			if !seen[h] {
				seen[h] = true
				skip = append(skip, h)
			}
		}
	}
	m.mu.Unlock()

	if skip == nil {
		skip = []string{} // send empty array, not null
	}

	body, err := json.Marshal(skip)
	if err != nil {
		return fmt.Errorf("marshal skip_hosts: %w", err)
	}

	// Skip the PATCH if the list hasn't changed — avoids Caddy logging
	// "config is unchanged" on every periodic ingress re-sync.
	m.mu.Lock()
	unchanged := m.lastSkip == string(body)
	m.mu.Unlock()
	if unchanged {
		return nil
	}

	adm := newAdminClient(m.adminAPI)
	// PATCH replaces an existing value; Enable() always initialises skip_hosts
	// so it is guaranteed to exist by the time rebuild() is called.
	for _, srv := range m.servers() {
		if err := adm.do(ctx, "PATCH",
			fmt.Sprintf("/config/apps/http/servers/%s/logs/skip_hosts", srv), body); err != nil {
			return fmt.Errorf("update skip_hosts (%s): %w", srv, err)
		}
	}

	m.mu.Lock()
	m.lastSkip = string(body)
	m.mu.Unlock()
	return nil
}
