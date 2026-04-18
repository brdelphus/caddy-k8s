// Package k8singress is a Caddy module that watches Kubernetes Ingress resources
// and dynamically configures Caddy routes, supporting both the modern
// ingressClassName field and the legacy kubernetes.io/ingress.class annotation.
package k8singress

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

func init() {
	caddy.RegisterModule(&App{})
}

// App is a Caddy app that watches Kubernetes Ingress resources with
// ingressClassName matching IngressClass and dynamically inserts/removes
// routes into the running Caddy HTTP server via the admin API.
type App struct {
	// IngressClass is the value of spec.ingressClassName (or the legacy
	// kubernetes.io/ingress.class annotation) to watch. Default: caddy.
	IngressClass string `json:"ingress_class,omitempty"`

	// ServerName is the name of the Caddy HTTP server block to inject HTTPS
	// routes into. If empty, the module discovers the server listening on :443.
	ServerName string `json:"server_name,omitempty"`

	// HTTPServerName is the name of the Caddy HTTP server block used for
	// ssl-redirect routes (port 80). Auto-discovered if empty.
	HTTPServerName string `json:"http_server_name,omitempty"`

	// AdminAPI is the Caddy admin API address. Default: localhost:2019.
	AdminAPI string `json:"admin_api,omitempty"`

	// Security controls which security middleware is injected into every
	// Ingress-generated route.
	Security SecurityConfig `json:"security,omitempty"`

	// Redis enables persistent storage of the Ingress → route ID mapping.
	// When set, route ownership survives Caddy restarts: stale routes from
	// Ingresses deleted while Caddy was down are cleaned up on next startup.
	// If omitted, an in-memory store is used (routes re-sync from the
	// Kubernetes API on every restart, but orphaned routes may accumulate).
	Redis *RedisConfig `json:"redis,omitempty"`

	// AccessLog enables HTTP access logging for all Ingress-generated routes.
	// Caddy writes one JSON log line per request to stderr. Individual Ingresses
	// can suppress logging via the caddy.ingress/access-log: "false" annotation.
	AccessLog bool `json:"access_log,omitempty"`

	logger         *zap.Logger
	client         kubernetes.Interface
	stopCh         chan struct{}
	// ctx is cancelled in Stop() so that in-flight admin API calls made by
	// this module instance are aborted before the new instance takes over.
	// Without this, old and new instances race on the same ingress during a
	// config reload and produce duplicate-@id errors.
	ctx            context.Context
	ctxCancel      context.CancelFunc
	mu             sync.Mutex
	keyMu          sync.Map // map[string]*sync.Mutex — serialises per ingress key
	store          routeStore
	// routeIDs is an in-process cache of store contents for fast lookups.
	routeIDs        map[string][]string
	serverName      string // resolved at Start() — HTTPS (:443)
	httpServerName  string // resolved at Start() — HTTP (:80), used for ssl-redirect
	tlsManager      *TLSManager
	tlsPolicyMgr    *TLSPolicyManager
	accessLogMgr    *accessLogManager
}

// SecurityConfig controls which security middleware is injected per route.
type SecurityConfig struct {
	// WAF enables Coraza WAF (requires coraza-caddy in the Caddy build).
	WAF bool `json:"waf,omitempty"`
	// WAFMode sets the rule engine mode: "Detection" (log only) or "On" (block).
	// Default: Detection.
	WAFMode string `json:"waf_mode,omitempty"`
	// SecurityHeaders injects HSTS, X-Content-Type-Options, X-Frame-Options,
	// Referrer-Policy and removes the Server header.
	SecurityHeaders bool `json:"security_headers,omitempty"`
	// InjectRealIP adds X-Real-IP and X-Forwarded-Proto headers to upstream
	// requests — required by Mailu and nginx-based backends.
	InjectRealIP bool `json:"inject_real_ip,omitempty"`
}

// CaddyModule returns the Caddy module info.
func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "k8s_ingress",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets defaults, initialises the route store, and resolves Caddy
// HTTP server names via the in-process Go API.
//
// Server name resolution happens here — NOT in Start() — because Start() is
// called while Caddy holds the config write-lock. Any GET /config/... admin
// API call from Start() waits for the read-lock → deadlock. Using ctx.App()
// accesses the already-provisioned HTTP app directly, with no HTTP round-trip.
func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	if a.IngressClass == "" {
		a.IngressClass = "caddy"
	}
	if a.AdminAPI == "" {
		a.AdminAPI = "localhost:2019"
	}
	if a.Security.WAFMode == "" {
		a.Security.WAFMode = "Detection"
	}
	a.routeIDs = make(map[string][]string)
	a.stopCh = make(chan struct{})

	if a.Redis != nil {
		rs, err := newRedisStore(a.Redis, a.IngressClass)
		if err != nil {
			// Redis is optional — warn and fall back to in-memory.
			a.logger.Warn("k8s_ingress: redis unavailable, falling back to in-memory store",
				zap.String("addr", a.Redis.Address),
				zap.Error(err),
			)
			a.store = newMemoryStore()
		} else {
			a.logger.Info("k8s_ingress: redis store enabled",
				zap.String("addr", a.Redis.Address),
			)
			a.store = rs
		}
	} else {
		a.store = newMemoryStore()
	}

	// Discover server names from the HTTP app if not explicitly configured.
	// ctx.App("http") provisions (if needed) and returns the caddyhttp.App
	// with Servers already populated from the Caddyfile JSON — no HTTP call.
	if a.ServerName == "" || a.HTTPServerName == "" {
		if httpAppIface, err := ctx.App("http"); err == nil {
			httpApp := httpAppIface.(*caddyhttp.App)
			for name, srv := range httpApp.Servers {
				for _, addr := range srv.Listen {
					if a.serverName == "" && strings.HasSuffix(addr, ":443") {
						a.serverName = name
					}
					if a.httpServerName == "" && strings.HasSuffix(addr, ":80") {
						a.httpServerName = name
					}
				}
			}
		} else {
			a.logger.Warn("k8s_ingress: could not access HTTP app for server discovery; will retry in Start()",
				zap.Error(err))
		}
	}
	// Explicit config values override auto-discovery.
	if a.ServerName != "" {
		a.serverName = a.ServerName
	}
	if a.HTTPServerName != "" {
		a.httpServerName = a.HTTPServerName
	}

	if a.serverName != "" || a.httpServerName != "" {
		a.logger.Info("k8s_ingress: resolved server names",
			zap.String("https_server", a.serverName),
			zap.String("http_server", a.httpServerName),
		)
	}

	return nil
}

// Start launches the Kubernetes informer.
//
// NOTE: Start() is invoked by Caddy while holding the config write-lock.
// Any call to the admin API from within Start() will deadlock because
// GET /config/... waits for the read-lock which is blocked by the write-lock.
// Server names were resolved in Provision() via ctx.App("http") — no admin
// API call needed here. The informer is still run asynchronously to avoid
// blocking Caddy startup on the initial k8s list/watch network round-trip.
// If server names were not discoverable at Provision time, run() falls back
// to polling the admin API (which is safe from a goroutine since Caddy has
// released the config write-lock by then).
func (a *App) Start() error {
	a.ctx, a.ctxCancel = context.WithCancel(context.Background())

	cfg, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig for local development / testing.
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("k8s_ingress: build kube config: %w", err)
		}
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("k8s_ingress: create k8s client: %w", err)
	}
	a.client = client

	go a.run(client)
	return nil
}

// run executes the full informer startup after Start() has returned and Caddy
// has released the config write-lock.
func (a *App) run(client kubernetes.Interface) {
	// If Provision() could not discover server names (e.g. HTTP app not
	// configured yet), fall back to polling the admin API with retries.
	// This is safe here because Caddy has released the write-lock by now.
	if a.serverName == "" {
		adm := newAdminClient(a.AdminAPI)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			name, err := resolveServerName(ctx, adm, a.ServerName, ":443")
			cancel()
			if err == nil {
				a.mu.Lock()
				a.serverName = name
				a.mu.Unlock()
				break
			}
			a.logger.Warn("k8s_ingress: waiting for HTTPS server (will retry)", zap.Error(err))
			select {
			case <-a.stopCh:
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
	if a.httpServerName == "" {
		adm := newAdminClient(a.AdminAPI)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		httpName, err := resolveServerName(ctx, adm, a.HTTPServerName, ":80")
		cancel()
		if err != nil {
			a.logger.Warn("k8s_ingress: HTTP server not found, ssl-redirect will be skipped", zap.Error(err))
		} else {
			a.mu.Lock()
			a.httpServerName = httpName
			a.mu.Unlock()
		}
	}

	// Restore persisted route ownership from the store so we can clean up
	// routes belonging to Ingresses that were deleted while Caddy was down.
	if stored, err := a.store.loadAll(context.Background()); err != nil {
		a.logger.Warn("k8s_ingress: could not restore route IDs from store", zap.Error(err))
	} else if len(stored) > 0 {
		a.mu.Lock()
		for k, v := range stored {
			a.routeIDs[k] = v
		}
		a.mu.Unlock()
		a.logger.Info("k8s_ingress: restored route IDs from store", zap.Int("ingresses", len(stored)))
	}

	// Initialize TLS manager for spec.tls support.
	a.tlsManager = NewTLSManager(client, a.AdminAPI, a.logger)
	go a.tlsManager.WatchSecrets(context.Background())

	// Initialize TLS policy manager for per-Ingress CertMagic automation policies.
	a.tlsPolicyMgr = NewTLSPolicyManager(client, a.AdminAPI, a.logger)

	// Initialize access log manager and enable server-level access logging.
	if a.AccessLog {
		a.accessLogMgr = newAccessLogManager(a.serverName, a.AdminAPI, a.logger)
		if err := a.accessLogMgr.Enable(context.Background()); err != nil {
			a.logger.Error("k8s_ingress: failed to enable access logging", zap.Error(err))
		}
	}

	a.logger.Info("k8s_ingress: watching ingresses",
		zap.String("class", a.IngressClass),
		zap.String("https_server", a.serverName),
		zap.String("http_server", a.httpServerName),
	)

	factory := informers.NewSharedInformerFactory(client, 30*time.Second)
	ingInformer := factory.Networking().V1().Ingresses().Informer()
	ingInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { a.handleAdd(obj) },
		UpdateFunc: func(_, obj interface{}) { a.handleAdd(obj) },
		DeleteFunc: func(obj interface{}) { a.handleDelete(obj) },
	})

	factory.Start(a.stopCh)
	// Block until initial list is synced so the first push is complete.
	if !cache.WaitForCacheSync(a.stopCh, ingInformer.HasSynced) {
		a.logger.Error("k8s_ingress: cache sync timed out")
		return
	}
}

// Stop shuts down the informer and closes the store connection.
func (a *App) Stop() error {
	// Cancel the module context first so any in-flight admin API calls in
	// handleAdd/handleDelete are aborted before the new module instance starts.
	if a.ctxCancel != nil {
		a.ctxCancel()
	}
	close(a.stopCh)
	if a.tlsManager != nil {
		a.tlsManager.Stop()
	}
	if err := a.store.close(); err != nil {
		a.logger.Warn("k8s_ingress: store close", zap.Error(err))
	}
	return nil
}

func (a *App) isOurs(ing *networkingv1.Ingress) bool {
	if ing.Spec.IngressClassName != nil && *ing.Spec.IngressClassName == a.IngressClass {
		return true
	}
	return ing.Annotations["kubernetes.io/ingress.class"] == a.IngressClass
}

func (a *App) handleAdd(obj interface{}) {
	ing, ok := obj.(*networkingv1.Ingress)
	if !ok || !a.isOurs(ing) {
		return
	}
	key := ing.Namespace + "/" + ing.Name

	mu := a.ingressMu(key)
	mu.Lock()
	defer mu.Unlock()

	var hosts []string
	for _, rule := range ing.Spec.Rules {
		hosts = append(hosts, rule.Host)
	}
	a.logger.Info("k8s_ingress: syncing ingress",
		zap.String("ingress", key),
		zap.Strings("hosts", hosts),
		zap.String("class", a.IngressClass),
	)

	ctx := a.ctx
	adm := newAdminClient(a.AdminAPI)

	// When WAF is enabled and no waf-rules-configmap annotation is set yet,
	// create the ConfigMap with default directives and patch the Ingress.
	// Inject the CM name into the local Ingress copy so resolveAnnotations
	// picks it up in this same sync cycle without waiting for the next event.
	if cmName, err := a.ensureWAFConfigMap(ctx, ing); err != nil {
		a.logger.Warn("k8s_ingress: ensure WAF configmap failed",
			zap.String("ingress", key),
			zap.Error(err),
		)
	} else if cmName != "" {
		if ing.Annotations == nil {
			ing.Annotations = make(map[string]string)
		}
		ing.Annotations[annotationWAFRulesConfigMap] = cmName
	}

	ann := resolveAnnotations(ctx, a.client, ing, a.logger)

	if fields := ann.annotationFields(); len(fields) > 0 {
		a.logger.Info("k8s_ingress: ingress annotations",
			append([]zap.Field{zap.String("ingress", key)}, fields...)...)
	}

	// Load TLS cert from spec.tls when the handler is cert-manager (or unset
	// with a secretName present — backwards compatibility).
	// CertMagic manages its own certs; no loading needed.
	if len(ing.Spec.TLS) > 0 && ann.tlsHandler != "certmagic" {
		if err := a.tlsManager.LoadFromIngress(ctx, ing); err != nil {
			a.logger.Error("k8s_ingress: failed to load TLS from ingress",
				zap.String("ingress", key),
				zap.Error(err),
			)
		}
	}

	// Per-Ingress access log suppression.
	if a.accessLogMgr != nil {
		hosts := ingressHosts(ing)
		if ann.accessLogDisabled && len(hosts) > 0 {
			if err := a.accessLogMgr.Skip(ctx, key, hosts); err != nil {
				a.logger.Warn("k8s_ingress: skip access log", zap.String("ingress", key), zap.Error(err))
			}
		} else {
			if err := a.accessLogMgr.Unskip(ctx, key); err != nil {
				a.logger.Warn("k8s_ingress: unskip access log", zap.String("ingress", key), zap.Error(err))
			}
		}
	}

	// Sync per-Ingress CertMagic automation policy when on-demand or a custom
	// CA is requested. Plain certmagic (no extra annotations) falls through to
	// the global automation policy configured in the Caddyfile.
	if len(ing.Spec.TLS) > 0 && ann.tlsHandler == "certmagic" && (ann.tlsOnDemand || ann.tlsCA != "") {
		if err := a.tlsPolicyMgr.Sync(ctx, ing, ann); err != nil {
			a.logger.Error("k8s_ingress: failed to sync TLS automation policy",
				zap.String("ingress", key),
				zap.Error(err),
			)
		}
	}
	routes := convertIngress(ing, a.Security, ann)

	// ssl-redirect: also inject HTTP→HTTPS redirect routes on the HTTP server.
	if ann.sslRedirect && a.httpServerName != "" {
		for _, r := range httpRedirectRoutes(ing) {
			if err := adm.upsertRoute(ctx, a.httpServerName, r); err != nil {
				a.logger.Warn("k8s_ingress: upsert ssl-redirect route",
					zap.String("id", r.ID), zap.Error(err))
			}
		}
	}

	a.mu.Lock()
	oldIDs := a.routeIDs[key]
	a.mu.Unlock()

	newIDs := make([]string, 0, len(routes))
	for _, r := range routes {
		newIDs = append(newIDs, r.ID)
	}

	// Remove routes that no longer exist (e.g. host/path removed in update).
	oldSet := stringSet(oldIDs)
	newSet := stringSet(newIDs)
	for id := range oldSet {
		if !newSet[id] {
			if err := adm.deleteRoute(ctx, id); err != nil {
				a.logger.Warn("k8s_ingress: delete stale route", zap.String("id", id), zap.Error(err))
			}
		}
	}

	// Ingresses with spec.tls go to the HTTPS server; all others to HTTP.
	targetServer := a.serverName
	if len(ing.Spec.TLS) == 0 {
		if a.httpServerName == "" {
			a.logger.Error("k8s_ingress: no HTTP server found for plain-HTTP ingress — route skipped",
				zap.String("ingress", key))
			return
		}
		targetServer = a.httpServerName
	}

	// Upsert each route.
	for _, r := range routes {
		if err := adm.upsertRoute(ctx, targetServer, r); err != nil {
			a.logger.Error("k8s_ingress: upsert route", zap.String("id", r.ID), zap.Error(err))
		}
	}

	a.mu.Lock()
	a.routeIDs[key] = newIDs
	a.mu.Unlock()

	if err := a.store.save(ctx, key, newIDs); err != nil {
		a.logger.Warn("k8s_ingress: store save", zap.String("ingress", key), zap.Error(err))
	}

	a.logger.Info("k8s_ingress: synced ingress", zap.String("ingress", key), zap.Int("routes", len(routes)))
}

func (a *App) handleDelete(obj interface{}) {
	ing, ok := obj.(*networkingv1.Ingress)
	if !ok {
		return
	}
	key := ing.Namespace + "/" + ing.Name

	mu := a.ingressMu(key)
	mu.Lock()
	defer mu.Unlock()

	ctx := a.ctx

	// Clean up TLS certificates and automation policies.
	if len(ing.Spec.TLS) > 0 {
		a.tlsManager.RemoveFromIngress(ing)
		if err := a.tlsPolicyMgr.Remove(ctx, ing); err != nil {
			a.logger.Warn("k8s_ingress: remove TLS policy", zap.String("ingress", key), zap.Error(err))
		}
	}

	// Remove access log suppression for deleted Ingress.
	if a.accessLogMgr != nil {
		if err := a.accessLogMgr.Unskip(ctx, key); err != nil {
			a.logger.Warn("k8s_ingress: unskip access log on delete", zap.String("ingress", key), zap.Error(err))
		}
	}

	adm := newAdminClient(a.AdminAPI)

	a.mu.Lock()
	ids := a.routeIDs[key]
	delete(a.routeIDs, key)
	a.mu.Unlock()

	for _, id := range ids {
		if err := adm.deleteRoute(ctx, id); err != nil {
			a.logger.Warn("k8s_ingress: delete route", zap.String("id", id), zap.Error(err))
		}
	}

	if err := a.store.remove(ctx, key); err != nil {
		a.logger.Warn("k8s_ingress: store remove", zap.String("ingress", key), zap.Error(err))
	}

	a.logger.Info("k8s_ingress: removed ingress", zap.String("ingress", key))
}

// ingressHosts returns all unique hostnames from the Ingress spec.rules.
func ingressHosts(ing *networkingv1.Ingress) []string {
	seen := make(map[string]bool)
	var hosts []string
	for _, rule := range ing.Spec.Rules {
		if rule.Host != "" && !seen[rule.Host] {
			seen[rule.Host] = true
			hosts = append(hosts, rule.Host)
		}
	}
	return hosts
}

func stringSet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// ingressMu returns (creating if needed) a per-ingress mutex stored in keyMu.
func (a *App) ingressMu(key string) *sync.Mutex {
	v, _ := a.keyMu.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// Interface assertions.
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
