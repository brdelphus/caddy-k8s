package k8singress

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/zap"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// All annotations use the caddy.ingress/ prefix.
const (
	// ── Access control ───────────────────────────────────────────────────────────

	// Allow only listed CIDRs; all other source IPs receive 403.
	// Value: comma-separated CIDRs, e.g. "10.0.0.0/8,192.168.0.0/16"
	annotationWhitelist = "caddy.ingress/whitelist-source-range"

	// Deny listed CIDRs with 403; all other IPs pass through.
	// Value: comma-separated CIDRs, e.g. "1.2.3.4/32"
	annotationBlocklist = "caddy.ingress/blocklist-source-range"

	// ── TLS ──────────────────────────────────────────────────────────────────────

	// Redirect plain HTTP requests to HTTPS with 301.
	// Value: "true" | "false" (default: "false")
	annotationSSLRedirect = "caddy.ingress/ssl-redirect"

	// ── Proxy timeouts ───────────────────────────────────────────────────────────

	// Timeout waiting for the upstream to send response headers.
	// Value: integer seconds, e.g. "300"
	annotationProxyReadTimeout = "caddy.ingress/proxy-read-timeout"

	// Timeout for transmitting the request to the upstream.
	// Value: integer seconds, e.g. "300"
	annotationProxySendTimeout = "caddy.ingress/proxy-send-timeout"

	// Timeout for establishing a connection to the upstream.
	// Value: integer seconds, e.g. "60"
	annotationProxyConnectTimeout = "caddy.ingress/proxy-connect-timeout"

	// ── Request body ─────────────────────────────────────────────────────────────

	// Maximum allowed request body size. "0" disables the limit.
	// Value: integer bytes or with suffix k/m/g, e.g. "2048m", "4g", "512k"
	annotationProxyBodySize = "caddy.ingress/proxy-body-size"

	// ── Basic auth ───────────────────────────────────────────────────────────────

	// Name of a k8s Secret (same namespace) whose "auth" key holds htpasswd
	// bcrypt entries. Only $2y$ / $2a$ hashes are supported.
	// Generate with: htpasswd -nbB username password
	annotationBasicAuthSecret = "caddy.ingress/basic-auth-secret"

	// WWW-Authenticate realm string. Default: "Restricted"
	annotationBasicAuthRealm = "caddy.ingress/basic-auth-realm"
)

// ingressAnnotations holds parsed, resolved values from an Ingress's annotations.
type ingressAnnotations struct {
	whitelist   []string
	blocklist   []string
	sslRedirect bool
	proxy       proxyConfig
	basicAuth   *basicAuthConfig
}

// proxyConfig holds upstream connection/timeout/body settings.
type proxyConfig struct {
	// Caddy duration strings ("300s"). Empty = use Caddy default.
	readTimeout    string
	sendTimeout    string
	connectTimeout string
	// Maximum request body size in bytes. 0 = no limit.
	maxBodySize int64
}

// basicAuthConfig holds parsed htpasswd accounts for Caddy's http_basic provider.
type basicAuthConfig struct {
	realm    string
	accounts []basicAuthAccount
}

type basicAuthAccount struct {
	Username string `json:"username"`
	Password string `json:"password"` // bcrypt hash
}

// resolveAnnotations parses Ingress annotations and fetches any referenced
// Kubernetes Secrets. Problems are logged as warnings — a single misconfigured
// Ingress never blocks others.
func resolveAnnotations(ctx context.Context, client kubernetes.Interface, ing *networkingv1.Ingress, log *zap.Logger) ingressAnnotations {
	a := ing.Annotations
	var out ingressAnnotations

	// ── Access control ───────────────────────────────────────────────────────────

	if v := a[annotationWhitelist]; v != "" {
		out.whitelist = parseCIDRList(v)
	}
	if v := a[annotationBlocklist]; v != "" {
		out.blocklist = parseCIDRList(v)
	}

	// ── TLS ──────────────────────────────────────────────────────────────────────

	if v := a[annotationSSLRedirect]; v != "" {
		out.sslRedirect = strings.EqualFold(v, "true")
	}

	// ── Proxy timeouts ───────────────────────────────────────────────────────────

	if v := a[annotationProxyReadTimeout]; v != "" {
		out.proxy.readTimeout = parseTimeoutSeconds(v)
	}
	if v := a[annotationProxySendTimeout]; v != "" {
		out.proxy.sendTimeout = parseTimeoutSeconds(v)
	}
	if v := a[annotationProxyConnectTimeout]; v != "" {
		out.proxy.connectTimeout = parseTimeoutSeconds(v)
	}

	// ── Request body ─────────────────────────────────────────────────────────────

	if v := a[annotationProxyBodySize]; v != "" {
		size, err := parseBodySize(v)
		if err != nil {
			log.Warn("k8s_ingress: invalid proxy-body-size",
				zap.String("ingress", ing.Namespace+"/"+ing.Name),
				zap.String("value", v),
				zap.Error(err),
			)
		} else {
			out.proxy.maxBodySize = size
		}
	}

	// ── Basic auth ───────────────────────────────────────────────────────────────

	if secretName := a[annotationBasicAuthSecret]; secretName != "" {
		realm := a[annotationBasicAuthRealm]
		if realm == "" {
			realm = "Restricted"
		}
		accounts, err := fetchBasicAuthAccounts(ctx, client, ing.Namespace, secretName, log)
		if err != nil {
			log.Warn("k8s_ingress: basic-auth-secret fetch failed — skipping auth",
				zap.String("ingress", ing.Namespace+"/"+ing.Name),
				zap.String("secret", secretName),
				zap.Error(err),
			)
		} else {
			out.basicAuth = &basicAuthConfig{realm: realm, accounts: accounts}
		}
	}

	return out
}

// parseCIDRList splits a comma-separated CIDR string and trims whitespace.
func parseCIDRList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseTimeoutSeconds converts an integer-seconds string to a Caddy duration
// string, e.g. "300" → "300s". Strings that already carry a unit are passed
// through unchanged.
func parseTimeoutSeconds(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return ""
	}
	last := s[len(s)-1]
	if last < '0' || last > '9' {
		return s // already has a unit suffix
	}
	return s + "s"
}

// parseBodySize converts a size string with optional unit suffix to bytes.
// Supported suffixes: k/K (kibibytes), m/M (mebibytes), g/G (gibibytes).
// "0" means no limit.
func parseBodySize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "0" {
		return 0, nil
	}
	if s == "" {
		return 0, fmt.Errorf("empty value")
	}

	multiplier := int64(1)
	switch last := s[len(s)-1]; {
	case last == 'k' || last == 'K':
		multiplier = 1024
		s = s[:len(s)-1]
	case last == 'm' || last == 'M':
		multiplier = 1024 * 1024
		s = s[:len(s)-1]
	case last == 'g' || last == 'G':
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	}

	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %q: %w", s, err)
	}
	return n * multiplier, nil
}

// fetchBasicAuthAccounts reads a Kubernetes Secret and parses its "auth" key
// as an htpasswd file. Only bcrypt ($2y$ / $2a$) entries are supported.
func fetchBasicAuthAccounts(ctx context.Context, client kubernetes.Interface, namespace, secretName string, log *zap.Logger) ([]basicAuthAccount, error) {
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get secret %s/%s: %w", namespace, secretName, err)
	}

	raw, ok := secret.Data["auth"]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s has no 'auth' key", namespace, secretName)
	}

	var accounts []basicAuthAccount
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		username := line[:idx]
		hash := line[idx+1:]

		if !strings.HasPrefix(hash, "$2y$") && !strings.HasPrefix(hash, "$2a$") {
			log.Warn("k8s_ingress: skipping non-bcrypt entry (use htpasswd -nbB to generate)",
				zap.String("secret", namespace+"/"+secretName),
				zap.String("username", username),
			)
			continue
		}
		accounts = append(accounts, basicAuthAccount{Username: username, Password: hash})
	}

	if len(accounts) == 0 {
		return nil, fmt.Errorf("secret %s/%s: no valid bcrypt accounts found", namespace, secretName)
	}
	return accounts, nil
}
