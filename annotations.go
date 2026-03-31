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

	// ── Backend protocol ─────────────────────────────────────────────────────────

	// Backend connection protocol. "HTTPS" enables TLS on the upstream transport.
	// Value: "HTTP" | "HTTPS" (default: "HTTP")
	annotationBackendProtocol = "caddy.ingress/backend-protocol"

	// Skip TLS verification for the upstream. Use with backend-protocol: HTTPS
	// when the backend uses a self-signed certificate (e.g. Mailu front).
	// Value: "true" | "false" (default: "false")
	annotationBackendTLSInsecure = "caddy.ingress/backend-tls-insecure-skip-verify"

	// ── Redirects ────────────────────────────────────────────────────────────────

	// Redirect all paths in this Ingress to a fixed URL with 301.
	// Replaces the reverse_proxy handler entirely — use for .well-known redirects.
	// Value: full URL, e.g. "https://example.com/remote.php/dav"
	annotationPermanentRedirect = "caddy.ingress/permanent-redirect"

	// Redirect all paths in this Ingress to a fixed URL with 302 (temporary).
	// Value: full URL, e.g. "https://example.com/new-location"
	annotationTemporalRedirect = "caddy.ingress/temporal-redirect"

	// Override the HTTP status code used by permanent-redirect or temporal-redirect.
	// Value: 3xx integer, e.g. "307" or "308"
	annotationRedirectCode = "caddy.ingress/redirect-code"

	// ── Rewrite ──────────────────────────────────────────────────────────────────

	// Rewrite the request URI before proxying to the upstream.
	// Replaces the entire URI path — capture group substitution is not supported.
	// Value: URI path, e.g. "/", "/api/v1"
	annotationRewriteTarget = "caddy.ingress/rewrite-target"

	// ── Upstream headers ─────────────────────────────────────────────────────────

	// Override the Host header sent to the upstream service.
	// Value: hostname, e.g. "internal.example.com"
	annotationUpstreamVhost = "caddy.ingress/upstream-vhost"

	// Set the X-Forwarded-Prefix header sent to the upstream service.
	// Value: path prefix, e.g. "/myapp"
	annotationXForwardedPrefix = "caddy.ingress/x-forwarded-prefix"

	// ── Virtual hosting ───────────────────────────────────────────────────────────

	// Additional hostnames this Ingress should respond to (comma-separated).
	// These hosts are added to the same route as the Ingress rules.
	// Value: "alias1.example.com,alias2.example.com"
	annotationServerAlias = "caddy.ingress/server-alias"

	// ── Rate limiting ─────────────────────────────────────────────────────────────

	// Maximum requests per second per client IP. Uses caddy-ratelimit (1-second
	// sliding window, keyed by client IP).
	// Value: integer, e.g. "100"
	annotationLimitRPS = "caddy.ingress/limit-rps"

	// ── Upstream resilience ──────────────────────────────────────────────────────

	// Number of times to retry failed upstream requests before returning an error.
	// Value: integer, e.g. "3"
	annotationProxyNextUpstreamTries = "caddy.ingress/proxy-next-upstream-tries"

	// ── Proxy transport ──────────────────────────────────────────────────────────

	// Force a specific HTTP version for upstream requests.
	// "1.1" is required for streaming and WebSocket backends (e.g. AzuraCast).
	// Value: "1.1" | "2" (default: unset — Caddy negotiates)
	annotationProxyHTTPVersion = "caddy.ingress/proxy-http-version"

	// ── WAF override ─────────────────────────────────────────────────────────────

	// Override the global WAF setting for this Ingress.
	// "off"       = disable WAF for this route even if enabled globally
	// "on"        = enable WAF in blocking mode
	// "detection" = enable WAF in detection-only (log) mode
	// Omit to inherit the global k8s_ingress security.waf setting.
	annotationWAF = "caddy.ingress/waf"

	// ── CORS ─────────────────────────────────────────────────────────────────────

	// Enable Cross-Origin Resource Sharing for this Ingress.
	// Value: "true" | "false"
	annotationEnableCORS = "caddy.ingress/enable-cors"

	// Allowed origins. "*" allows all origins (default).
	// Comma-separated for multiple specific origins:
	//   "https://app.example.com,https://admin.example.com"
	// Note: cors-allow-credentials=true is incompatible with "*".
	annotationCORSAllowOrigin = "caddy.ingress/cors-allow-origin"

	// HTTP methods allowed in CORS requests.
	// Default: "GET, PUT, POST, DELETE, PATCH, OPTIONS"
	annotationCORSAllowMethods = "caddy.ingress/cors-allow-methods"

	// Request headers allowed in CORS requests.
	// Default: "DNT,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization"
	annotationCORSAllowHeaders = "caddy.ingress/cors-allow-headers"

	// Response headers the browser is allowed to access.
	// Default: empty (not exposed)
	annotationCORSExposeHeaders = "caddy.ingress/cors-expose-headers"

	// Allow the browser to send credentials (cookies, TLS client certs).
	// Incompatible with cors-allow-origin: "*".
	// Value: "true" | "false" (default: "false")
	annotationCORSAllowCredentials = "caddy.ingress/cors-allow-credentials"

	// How long (seconds) the browser may cache a preflight response.
	// Default: 1728000 (20 days — nginx-ingress default)
	annotationCORSMaxAge = "caddy.ingress/cors-max-age"

	// ── TLS handler ──────────────────────────────────────────────────────────────

	// Declares which TLS handler manages the certificate for this Ingress.
	// spec.tls is always required for HTTPS — this annotation tells caddy-k8s
	// how the cert is being provisioned so it can act accordingly.
	//
	// Values:
	//   certmagic    — CertMagic handles issuance via ACME. spec.tls hosts
	//                  declare the domains; no secretName needed.
	//   cert-manager — cert-manager creates the Secret referenced in
	//                  spec.tls.secretName. caddy-k8s loads the cert from it.
	annotationTLSHandler = "caddy.ingress/tls"

	// ── Basic auth ───────────────────────────────────────────────────────────────

	// Name of a k8s Secret (same namespace) whose "auth" key holds htpasswd
	// bcrypt entries. Only $2y$ / $2a$ hashes are supported.
	// Generate with: htpasswd -nbB username password
	annotationBasicAuthSecret = "caddy.ingress/basic-auth-secret"

	// WWW-Authenticate realm string. Default: "Restricted"
	annotationBasicAuthRealm = "caddy.ingress/basic-auth-realm"
)

// corsConfig holds parsed CORS annotation values.
type corsConfig struct {
	origins       []string // ["*"] or one or more specific origins
	allowMethods  string
	allowHeaders  string
	exposeHeaders string
	allowCreds    bool
	maxAge        int
}

func (c *corsConfig) isWildcard() bool {
	return len(c.origins) == 1 && c.origins[0] == "*"
}

// ingressAnnotations holds parsed, resolved values from an Ingress's annotations.
type ingressAnnotations struct {
	// namespace/name stored here so handlers can derive stable zone names.
	namespace string
	name      string

	whitelist         []string
	blocklist         []string
	sslRedirect       bool
	permanentRedirect string
	temporalRedirect  string
	redirectCode      int // 0 = use type default (301/302)
	rewriteTarget     string
	serverAliases     []string
	limitRPS          int         // 0 = disabled
	cors       *corsConfig // nil = CORS disabled
	tlsHandler string      // "certmagic" | "cert-manager" | ""
	// wafOverride overrides the global WAF setting for this Ingress.
	// nil = inherit global; non-nil = use this value.
	wafOverride *bool
	// wafModeOverride overrides the global WAF mode when wafOverride is non-nil.
	// Empty = use global WAFMode.
	wafModeOverride string
	proxy             proxyConfig
	basicAuth         *basicAuthConfig
}

// proxyConfig holds upstream connection/timeout/body settings.
type proxyConfig struct {
	// Caddy duration strings ("300s"). Empty = use Caddy default.
	readTimeout    string
	sendTimeout    string
	connectTimeout string
	// Maximum request body size in bytes. 0 = no limit.
	maxBodySize int64
	// backendTLS enables TLS on the upstream transport (backend-protocol: HTTPS).
	backendTLS bool
	// backendTLSInsecure skips upstream certificate verification.
	backendTLSInsecure bool
	// httpVersion forces a specific HTTP version to upstream, e.g. "1.1".
	httpVersion string
	// upstreamVhost overrides the Host header sent to the upstream.
	upstreamVhost string
	// xForwardedPrefix sets X-Forwarded-Prefix on upstream requests.
	xForwardedPrefix string
	// retries is the number of times to retry failed upstream requests.
	// 0 = Caddy default (no retries).
	retries int
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
	out := ingressAnnotations{
		namespace: ing.Namespace,
		name:      ing.Name,
	}

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

	// ── Backend protocol ─────────────────────────────────────────────────────────

	if strings.EqualFold(a[annotationBackendProtocol], "https") {
		out.proxy.backendTLS = true
	}
	if strings.EqualFold(a[annotationBackendTLSInsecure], "true") {
		out.proxy.backendTLSInsecure = true
	}

	// ── Redirects ────────────────────────────────────────────────────────────────

	if v := a[annotationPermanentRedirect]; v != "" {
		out.permanentRedirect = strings.TrimSpace(v)
	}
	if v := a[annotationTemporalRedirect]; v != "" {
		out.temporalRedirect = strings.TrimSpace(v)
	}
	if v := a[annotationRedirectCode]; v != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil && n >= 300 && n < 400 {
			out.redirectCode = n
		} else {
			log.Warn("k8s_ingress: invalid redirect-code — must be 3xx integer",
				zap.String("ingress", ing.Namespace+"/"+ing.Name),
				zap.String("value", v),
			)
		}
	}

	// ── Rewrite ──────────────────────────────────────────────────────────────────

	if v := a[annotationRewriteTarget]; v != "" {
		out.rewriteTarget = strings.TrimSpace(v)
	}

	// ── Upstream headers ─────────────────────────────────────────────────────────

	if v := a[annotationUpstreamVhost]; v != "" {
		out.proxy.upstreamVhost = strings.TrimSpace(v)
	}
	if v := a[annotationXForwardedPrefix]; v != "" {
		out.proxy.xForwardedPrefix = strings.TrimSpace(v)
	}

	// ── Virtual hosting ───────────────────────────────────────────────────────────

	if v := a[annotationServerAlias]; v != "" {
		for _, alias := range strings.Split(v, ",") {
			if alias = strings.TrimSpace(alias); alias != "" {
				out.serverAliases = append(out.serverAliases, alias)
			}
		}
	}

	// ── Rate limiting ─────────────────────────────────────────────────────────────

	if v := a[annotationLimitRPS]; v != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil && n > 0 {
			out.limitRPS = n
		} else {
			log.Warn("k8s_ingress: invalid limit-rps — must be positive integer",
				zap.String("ingress", ing.Namespace+"/"+ing.Name),
				zap.String("value", v),
			)
		}
	}

	// ── Upstream resilience ──────────────────────────────────────────────────────

	if v := a[annotationProxyNextUpstreamTries]; v != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil && n > 0 {
			out.proxy.retries = n
		} else {
			log.Warn("k8s_ingress: invalid proxy-next-upstream-tries — must be positive integer",
				zap.String("ingress", ing.Namespace+"/"+ing.Name),
				zap.String("value", v),
			)
		}
	}

	// ── CORS ─────────────────────────────────────────────────────────────────────

	if strings.EqualFold(a[annotationEnableCORS], "true") {
		cfg := &corsConfig{
			allowMethods: "GET, PUT, POST, DELETE, PATCH, OPTIONS",
			allowHeaders: "DNT,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization",
			maxAge:       1728000,
		}

		// Parse allowed origins (comma-separated).
		if v := a[annotationCORSAllowOrigin]; v != "" {
			for _, o := range strings.Split(v, ",") {
				if o = strings.TrimSpace(o); o != "" {
					cfg.origins = append(cfg.origins, o)
				}
			}
		}
		if len(cfg.origins) == 0 {
			cfg.origins = []string{"*"}
		}

		// Credentials flag — incompatible with wildcard origin.
		if strings.EqualFold(a[annotationCORSAllowCredentials], "true") {
			if cfg.isWildcard() {
				log.Warn("k8s_ingress: cors-allow-credentials=true is incompatible with cors-allow-origin=* — credentials ignored",
					zap.String("ingress", ing.Namespace+"/"+ing.Name),
				)
			} else {
				cfg.allowCreds = true
			}
		}

		if v := a[annotationCORSAllowMethods]; v != "" {
			cfg.allowMethods = strings.TrimSpace(v)
		}
		if v := a[annotationCORSAllowHeaders]; v != "" {
			cfg.allowHeaders = strings.TrimSpace(v)
		}
		if v := a[annotationCORSExposeHeaders]; v != "" {
			cfg.exposeHeaders = strings.TrimSpace(v)
		}
		if v := a[annotationCORSMaxAge]; v != "" {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err == nil && n >= 0 {
				cfg.maxAge = n
			} else {
				log.Warn("k8s_ingress: invalid cors-max-age — using default",
					zap.String("ingress", ing.Namespace+"/"+ing.Name),
					zap.String("value", v),
				)
			}
		}

		out.cors = cfg
	}

	// ── Proxy transport ──────────────────────────────────────────────────────────

	if v := a[annotationProxyHTTPVersion]; v != "" {
		out.proxy.httpVersion = strings.TrimSpace(v)
	}

	// ── WAF override ─────────────────────────────────────────────────────────────

	if v := strings.ToLower(strings.TrimSpace(a[annotationWAF])); v != "" {
		switch v {
		case "off":
			f := false
			out.wafOverride = &f
		case "on":
			t := true
			out.wafOverride = &t
			out.wafModeOverride = "On"
		case "detection":
			t := true
			out.wafOverride = &t
			out.wafModeOverride = "DetectionOnly"
		default:
			log.Warn("k8s_ingress: unknown waf annotation value — ignored",
				zap.String("ingress", ing.Namespace+"/"+ing.Name),
				zap.String("value", v),
			)
		}
	}

	// ── TLS handler ──────────────────────────────────────────────────────────────

	out.tlsHandler = strings.ToLower(strings.TrimSpace(a[annotationTLSHandler]))

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
