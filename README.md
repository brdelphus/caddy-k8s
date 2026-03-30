# caddy-k8s

A [Caddy](https://caddyserver.com) module that turns Caddy into a Kubernetes Ingress controller. It watches `Ingress` resources with a matching `ingressClassName` and dynamically inserts and removes routes into the running Caddy instance via the admin API — no restarts, no manual Caddyfile editing.

Built to pair with [caddy-custom](https://github.com/brdelphus/caddy-custom), a production Caddy image that bundles WAF, L4 routing, rate limiting, GeoIP blocking, CrowdSec, and more.

---

## Features

- Watches Kubernetes `Ingress` resources using `ingressClassName: caddy-custom` (or the legacy `kubernetes.io/ingress.class` annotation)
- Routes appear in Caddy **within seconds** of creating or updating an Ingress — zero-downtime, no reload needed
- Per-route security middleware injection:
  - Security headers (HSTS, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, removes `Server`)
  - `X-Real-IP` + `X-Forwarded-*` injection to upstream — required by nginx-based backends (Mailu, etc.)
  - Optional [Coraza WAF](https://github.com/corazawaf/coraza-caddy) per route (Detection or blocking mode)
- Annotation-driven per-Ingress behaviour:
  - HTTPS backends with optional TLS verification skip (e.g. Mailu self-signed)
  - Permanent 301 redirects replacing the reverse proxy (e.g. `.well-known` → `/remote.php/dav`)
  - Forced HTTP/1.1 to upstream for streaming and WebSocket backends (e.g. AzuraCast)
  - Proxy timeouts, body size limits, IP whitelist/blocklist, Basic Auth
- Supports `pathType: Prefix`, `Exact`, and `ImplementationSpecific`
- Caddyfile global block configuration
- Falls back to `~/.kube/config` for local development

---

## Requirements

- Caddy built with this module via [xcaddy](https://github.com/caddyserver/xcaddy)
- Kubernetes 1.19+ (for `ingressClassName` field support)
- Caddy admin API enabled (default: `localhost:2019`)
- A `ServiceAccount` with permission to list/watch `Ingress` resources (see [RBAC](#rbac))

---

## Building

```bash
xcaddy build \
  --with github.com/brdelphus/caddy-k8s
```

Or alongside other plugins (see [caddy-custom](https://github.com/brdelphus/caddy-custom) for the full production build):

```bash
xcaddy build \
  --with github.com/brdelphus/caddy-k8s \
  --with github.com/corazawaf/coraza-caddy/v2@v2.3.0 \
  --with github.com/mholt/caddy-l4@v0.1.0
```

---

## Configuration

Add a `k8s_ingress` block to the Caddy global options block:

```
{
    k8s_ingress {
        ingress_class    caddy-custom     # default
        server_name      https            # optional, auto-detected from :443 if omitted
        admin_api        localhost:2019   # default

        security {
            waf              off          # on = Coraza WAF (requires coraza-caddy)
            waf_mode         Detection    # Detection | On
            security_headers on          # HSTS, X-Content-Type-Options, etc.
            inject_real_ip   on          # X-Real-IP + X-Forwarded-* to upstream
        }
    }
}
```

The module registers as a `caddy.App` (`k8s_ingress`), so it can also be configured in JSON if preferred.

---

## Creating Ingress resources

Standard Kubernetes `Ingress` — no custom annotations required:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: nextcloud
  namespace: nextcloud
spec:
  ingressClassName: caddy-custom
  rules:
    - host: cloud.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: nextcloud
                port:
                  number: 80
```

Routes are resolved to `<service>.<namespace>.svc.cluster.local:<port>` — no cross-namespace lookup needed.

### Multiple paths on one host

```yaml
spec:
  ingressClassName: caddy-custom
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: api-backend
                port:
                  number: 8080
          - path: /
            pathType: Prefix
            backend:
              service:
                name: frontend
                port:
                  number: 3000
```

---

## Annotations

All annotations use the `caddy.ingress/` prefix and are set per Ingress resource.

| Annotation | Default | Description |
|---|---|---|
| `caddy.ingress/ssl-redirect` | `false` | Redirect HTTP → HTTPS with 301 |
| `caddy.ingress/backend-protocol` | `HTTP` | `HTTPS` to enable TLS on the upstream transport |
| `caddy.ingress/backend-tls-insecure-skip-verify` | `false` | Skip upstream TLS verification (use with `backend-protocol: HTTPS`) |
| `caddy.ingress/permanent-redirect` | — | Redirect all paths in this Ingress to a fixed URL with 301 |
| `caddy.ingress/proxy-http-version` | — | Force HTTP version to upstream: `1.1` or `2` |
| `caddy.ingress/waf` | — | Per-route WAF override: `off`, `on`, or `detection` (overrides global setting) |
| `caddy.ingress/proxy-read-timeout` | — | Seconds to wait for upstream response headers |
| `caddy.ingress/proxy-send-timeout` | — | Seconds to transmit the request to upstream |
| `caddy.ingress/proxy-connect-timeout` | — | Seconds to establish upstream connection |
| `caddy.ingress/proxy-body-size` | — | Max request body size (`0` = unlimited, supports `k`/`m`/`g`) |
| `caddy.ingress/whitelist-source-range` | — | Comma-separated CIDRs to allow; all others get 403 |
| `caddy.ingress/blocklist-source-range` | — | Comma-separated CIDRs to deny; all others pass |
| `caddy.ingress/basic-auth-secret` | — | Secret name (same namespace) with `auth` htpasswd key |
| `caddy.ingress/basic-auth-realm` | `Restricted` | WWW-Authenticate realm string |

---

### IP whitelist

Allow only specific CIDRs — all other IPs receive `403 Forbidden`:

```yaml
metadata:
  annotations:
    caddy.ingress/whitelist-source-range: "192.168.1.0/24,10.0.0.0/8"
```

### IP blocklist

Deny specific CIDRs — all other IPs pass through:

```yaml
metadata:
  annotations:
    caddy.ingress/blocklist-source-range: "1.2.3.4/32,5.6.7.8/32"
```

Both can be combined. Whitelist is evaluated first, then blocklist.

### SSL redirect

Redirect HTTP traffic to HTTPS with a 301:

```yaml
metadata:
  annotations:
    caddy.ingress/ssl-redirect: "true"
```

### Proxy timeouts

```yaml
metadata:
  annotations:
    caddy.ingress/proxy-read-timeout: "300"      # seconds — waiting for upstream response headers
    caddy.ingress/proxy-send-timeout: "300"      # seconds — transmitting request to upstream
    caddy.ingress/proxy-connect-timeout: "60"    # seconds — establishing upstream connection
```

### Request body size

```yaml
metadata:
  annotations:
    caddy.ingress/proxy-body-size: "2048m"   # supports k / m / g suffixes, "0" = unlimited
```

### Backend protocol (HTTPS upstream)

When the backend speaks HTTPS (e.g. Mailu's front container), enable TLS on the upstream transport:

```yaml
metadata:
  annotations:
    caddy.ingress/backend-protocol: HTTPS
```

If the backend uses a self-signed certificate, add:

```yaml
metadata:
  annotations:
    caddy.ingress/backend-protocol: HTTPS
    caddy.ingress/backend-tls-insecure-skip-verify: "true"
```

This is equivalent to nginx's `nginx.ingress.kubernetes.io/backend-protocol: HTTPS`.

### Permanent redirect

Redirect all paths in an Ingress to a fixed URL with 301. The reverse proxy is replaced entirely — no upstream connection is made. Useful for `.well-known` redirects required by CalDAV/CardDAV clients:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: nextcloud-wellknown
  namespace: nextcloud
  annotations:
    caddy.ingress/permanent-redirect: "https://dav.example.com/remote.php/dav"
spec:
  ingressClassName: caddy-custom
  rules:
    - host: dav.example.com
      http:
        paths:
          - path: /.well-known/carddav
            pathType: Exact
            backend:
              service:
                name: nextcloud
                port:
                  number: 8080
          - path: /.well-known/caldav
            pathType: Exact
            backend:
              service:
                name: nextcloud
                port:
                  number: 8080
```

Every path listed in the Ingress will 301 to the annotation value — the backend field is ignored.

### Proxy HTTP version

Force a specific HTTP version for upstream connections. Use `1.1` for streaming endpoints and WebSocket backends that require connection-level persistence (e.g. AzuraCast's Icecast/HLS streams):

```yaml
metadata:
  annotations:
    caddy.ingress/proxy-http-version: "1.1"
```

Without this, Caddy may negotiate HTTP/2 to the upstream, which does not support the streaming upgrade mechanism.

> **Note:** Caddy proxies WebSocket connections automatically — no special annotation is needed. The `proxy-http-version: "1.1"` annotation is only required for raw streaming protocols like Icecast.

### WAF per-route override

Override the global WAF setting for a single Ingress. Useful when WAF is enabled globally but a specific backend is incompatible with WAF inspection (e.g. AzuraCast's streaming endpoints):

```yaml
metadata:
  annotations:
    caddy.ingress/waf: "off"        # disable WAF for this route
    # caddy.ingress/waf: "on"       # enable WAF in blocking mode
    # caddy.ingress/waf: "detection" # enable WAF in detection-only (log) mode
```

When omitted, the route inherits the `security.waf` setting from the `k8s_ingress` global config.

### Basic auth

Protect a route with HTTP Basic Auth backed by a Kubernetes Secret:

```yaml
metadata:
  annotations:
    caddy.ingress/basic-auth-secret: "my-app-basic-auth"   # Secret name (same namespace)
    caddy.ingress/basic-auth-realm: "My App"               # optional, default: Restricted
```

The Secret must have an `auth` key containing htpasswd-formatted entries. **Only bcrypt hashes are supported** (`$2y$` / `$2a$`) — Caddy's `http_basic` provider does not accept MD5 or SHA1.

Create the Secret:

```bash
# Generate a bcrypt entry
htpasswd -nbB myuser mysecretpassword
# → myuser:$2y$05$...

kubectl create secret generic my-app-basic-auth \
  --from-literal=auth='myuser:$2y$05$...'
```

Or with multiple users:

```bash
htpasswd -cbB auth.htpasswd alice password1
htpasswd -bB  auth.htpasswd bob   password2
kubectl create secret generic my-app-basic-auth --from-file=auth=auth.htpasswd
```

---

## How it works

1. **Start**: the module connects to the Kubernetes API (in-cluster service account or `~/.kube/config`)
2. **Sync**: lists all existing Ingress resources matching the configured `ingressClassName` and inserts their routes
3. **Watch**: an informer keeps a persistent connection to the API server — Add/Update/Delete events are processed immediately
4. **Upsert**: each route is tagged with a stable `@id` (`caddy-k8s-<namespace>-<name>-<host>`), so updates use `PUT /id/<id>` and new routes use `POST /config/apps/http/servers/<server>/routes/`
5. **Delete**: on Ingress removal, `DELETE /id/<id>` is called for each route — other routes are untouched

---

## RBAC

The module needs read access to `Ingress` resources. When deploying with [caddy-custom](https://github.com/brdelphus/caddy-custom)'s Helm chart, the `ClusterRole` and `ClusterRoleBinding` are created automatically when `k8sIngress.enabled: true`.

For manual deployments:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: caddy-ingress
rules:
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses", "ingressclasses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses/status"]
    verbs: ["update", "patch"]
  - apiGroups: [""]
    resources: ["services", "endpoints"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: caddy-ingress
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: caddy-ingress
subjects:
  - kind: ServiceAccount
    name: caddy
    namespace: caddy
```

---

## Acknowledgements

This module stands on the shoulders of excellent open-source projects:

| Project | Author | Role |
|---|---|---|
| [Caddy](https://github.com/caddyserver/caddy) | [Matt Holt](https://github.com/mholt) | The web server this module extends |
| [xcaddy](https://github.com/caddyserver/xcaddy) | Caddy team | Plugin build tool |
| [client-go](https://github.com/kubernetes/client-go) | Kubernetes Authors | Kubernetes API client and informer framework |
| [coraza-caddy](https://github.com/corazawaf/coraza-caddy) | [Coraza](https://github.com/corazawaf) / [jcchavezs](https://github.com/jcchavezs) | WAF handler injected per route (optional) |
| [caddy-l4](https://github.com/mholt/caddy-l4) | [Matt Holt](https://github.com/mholt) | Layer 4 TCP/UDP routing (used in caddy-custom) |
| [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) | [Matt Holt](https://github.com/mholt) | Sliding-window rate limiting (used in caddy-custom) |
| [cache-handler](https://github.com/caddyserver/cache-handler) | [Caddy / Sylvain Combraque](https://github.com/darkweak) | RFC 7234 HTTP cache via Souin (used in caddy-custom) |
| [caddy-maxmind-geolocation](https://github.com/porech/caddy-maxmind-geolocation) | [Massimiliano Porrini](https://github.com/porech) | GeoIP country blocking (used in caddy-custom) |
| [caddy-crowdsec-bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer) | [Herman Slatman](https://github.com/hslatman) | CrowdSec IP reputation + AppSec (used in caddy-custom) |
| [caddy-defender](https://github.com/jasonlovesdoggo/caddy-defender) | [Jason Cameron](https://github.com/jasonlovesdoggo) | AI scraper / cloud IP blocking (used in caddy-custom) |
| [go.uber.org/zap](https://github.com/uber-go/zap) | Uber | Structured logging |

---

## License

MIT
