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
	mu         sync.Mutex
	serverName string
	adminAPI   string
	logger     *zap.Logger
	// disabled maps ingress key (namespace/name) to the hosts it contributes
	// to skip_hosts.
	disabled map[string][]string
}

func newAccessLogManager(serverName, adminAPI string, logger *zap.Logger) *accessLogManager {
	return &accessLogManager{
		serverName: serverName,
		adminAPI:   adminAPI,
		logger:     logger,
		disabled:   make(map[string][]string),
	}
}

// Enable registers the "access" logger in Caddy's logging config and sets it
// as the default access log for the HTTP server. Called once during Start().
func (m *accessLogManager) Enable(ctx context.Context) error {
	adm := newAdminClient(m.adminAPI)

	// Register a named "access" logger that captures HTTP access log entries.
	loggerPayload := map[string]interface{}{
		"writer":  map[string]interface{}{"output": "stderr"},
		"encoder": map[string]interface{}{"format": "json"},
		"include": []string{"http.log.access"},
	}
	body, err := json.Marshal(loggerPayload)
	if err != nil {
		return fmt.Errorf("marshal access logger: %w", err)
	}
	if err := adm.do(ctx, "PUT", "/config/logging/logs/access", body); err != nil {
		return fmt.Errorf("configure access logger: %w", err)
	}

	// Point the HTTP server at the "access" logger.
	logsPayload := map[string]interface{}{
		"default_logger_name": "access",
	}
	body, err = json.Marshal(logsPayload)
	if err != nil {
		return fmt.Errorf("marshal server logs config: %w", err)
	}
	if err := adm.do(ctx, "PUT",
		fmt.Sprintf("/config/apps/http/servers/%s/logs", m.serverName), body); err != nil {
		return fmt.Errorf("configure server logs: %w", err)
	}

	m.logger.Info("k8s_ingress: access logging enabled",
		zap.String("server", m.serverName))
	return nil
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
	adm := newAdminClient(m.adminAPI)
	if err := adm.do(ctx, "PUT",
		fmt.Sprintf("/config/apps/http/servers/%s/logs/skip_hosts", m.serverName), body); err != nil {
		return fmt.Errorf("update skip_hosts: %w", err)
	}
	return nil
}
