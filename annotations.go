package k8singress

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Supported annotations on Ingress resources.
const (
	// annotationWhitelist allows only the listed CIDRs; all other IPs receive 403.
	// Value: comma-separated CIDRs, e.g. "192.168.1.0/24,10.0.0.0/8"
	annotationWhitelist = "caddy.ingress/whitelist-source-range"

	// annotationBlocklist denies the listed CIDRs with 403; all other IPs pass.
	// Value: comma-separated CIDRs, e.g. "1.2.3.4/32,5.6.7.8/32"
	annotationBlocklist = "caddy.ingress/blocklist-source-range"

	// annotationBasicAuthSecret names a Kubernetes Secret (in the same namespace)
	// whose "auth" key contains htpasswd-formatted bcrypt entries.
	// Only bcrypt ($2y$ / $2a$) hashes are supported by Caddy's http_basic provider.
	// Generate with: htpasswd -nbB username password
	// Value: secret name, e.g. "my-app-basic-auth"
	annotationBasicAuthSecret = "caddy.ingress/basic-auth-secret"

	// annotationBasicAuthRealm sets the WWW-Authenticate realm string.
	// Default: "Restricted"
	annotationBasicAuthRealm = "caddy.ingress/basic-auth-realm"
)

// ingressAnnotations holds parsed, resolved values from an Ingress's annotations.
type ingressAnnotations struct {
	// whitelist is non-nil when caddy.ingress/whitelist-source-range is set.
	whitelist []string
	// blocklist is non-nil when caddy.ingress/blocklist-source-range is set.
	blocklist []string
	// basicAuth is non-nil when caddy.ingress/basic-auth-secret is set and the
	// referenced Secret was successfully fetched and parsed.
	basicAuth *basicAuthConfig
}

// basicAuthConfig holds parsed htpasswd accounts for Caddy's http_basic provider.
type basicAuthConfig struct {
	realm    string
	accounts []basicAuthAccount
}

type basicAuthAccount struct {
	Username string `json:"username"`
	// Password must be a bcrypt hash ($2a$ or $2y$).
	Password string `json:"password"`
}

// resolveAnnotations parses Ingress annotations and fetches any referenced
// Kubernetes Secrets. It never returns an error — problems are logged as
// warnings so a single misconfigured Ingress doesn't block others.
func resolveAnnotations(ctx context.Context, client kubernetes.Interface, ing *networkingv1.Ingress, log *zap.Logger) ingressAnnotations {
	ann := ing.Annotations
	var out ingressAnnotations

	if v, ok := ann[annotationWhitelist]; ok {
		out.whitelist = parseCIDRList(v)
	}
	if v, ok := ann[annotationBlocklist]; ok {
		out.blocklist = parseCIDRList(v)
	}

	if secretName, ok := ann[annotationBasicAuthSecret]; ok {
		realm := ann[annotationBasicAuthRealm]
		if realm == "" {
			realm = "Restricted"
		}
		accounts, err := fetchBasicAuthAccounts(ctx, client, ing.Namespace, secretName, log)
		if err != nil {
			log.Warn("k8s_ingress: basic-auth-secret fetch failed — skipping auth for ingress",
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
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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
		// htpasswd format: username:hash
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		username := line[:idx]
		hash := line[idx+1:]

		// Caddy's http_basic only supports bcrypt.
		if !strings.HasPrefix(hash, "$2y$") && !strings.HasPrefix(hash, "$2a$") {
			log.Warn("k8s_ingress: skipping non-bcrypt htpasswd entry (use htpasswd -B to generate)",
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
