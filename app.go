// Package k8singress is a Caddy module that watches Kubernetes Ingress resources
// and dynamically configures Caddy routes, supporting both the modern
// ingressClassName field and the legacy kubernetes.io/ingress.class annotation.
package k8singress

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
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
	// kubernetes.io/ingress.class annotation) to watch. Default: caddy-custom.
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

	logger     *zap.Logger
	client     kubernetes.Interface
	stopCh     chan struct{}
	mu         sync.Mutex
	// routes maps "namespace/name" to the list of Caddy route IDs owned by
	// that Ingress, used for cleanup on delete.
	routeIDs       map[string][]string
	serverName     string // resolved at Start() — HTTPS (:443)
	httpServerName string // resolved at Start() — HTTP (:80), used for ssl-redirect
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

// Provision sets defaults.
func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	if a.IngressClass == "" {
		a.IngressClass = "caddy-custom"
	}
	if a.AdminAPI == "" {
		a.AdminAPI = "localhost:2019"
	}
	if a.Security.WAFMode == "" {
		a.Security.WAFMode = "Detection"
	}
	a.routeIDs = make(map[string][]string)
	a.stopCh = make(chan struct{})
	return nil
}

// Start launches the Kubernetes informer.
func (a *App) Start() error {
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

	// Resolve which Caddy server to inject routes into.
	adm := newAdminClient(a.AdminAPI)
	name, err := resolveServerName(context.Background(), adm, a.ServerName, ":443")
	if err != nil {
		return fmt.Errorf("k8s_ingress: resolve https server name: %w", err)
	}
	a.serverName = name

	httpName, err := resolveServerName(context.Background(), adm, a.HTTPServerName, ":80")
	if err != nil {
		// Not fatal — ssl-redirect simply won't work without an HTTP server.
		a.logger.Warn("k8s_ingress: HTTP server not found, ssl-redirect will be skipped", zap.Error(err))
	}
	a.httpServerName = httpName

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
		return fmt.Errorf("k8s_ingress: cache sync timed out")
	}

	return nil
}

// Stop shuts down the informer.
func (a *App) Stop() error {
	close(a.stopCh)
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
	adm := newAdminClient(a.AdminAPI)
	ann := resolveAnnotations(context.Background(), a.client, ing, a.logger)
	routes := convertIngress(ing, a.Security, ann)

	// ssl-redirect: also inject HTTP→HTTPS redirect routes on the HTTP server.
	if ann.sslRedirect && a.httpServerName != "" {
		for _, r := range httpRedirectRoutes(ing) {
			if err := adm.upsertRoute(context.Background(), a.httpServerName, r); err != nil {
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
			if err := adm.deleteRoute(context.Background(), id); err != nil {
				a.logger.Warn("k8s_ingress: delete stale route", zap.String("id", id), zap.Error(err))
			}
		}
	}

	// Upsert each route.
	for _, r := range routes {
		if err := adm.upsertRoute(context.Background(), a.serverName, r); err != nil {
			a.logger.Error("k8s_ingress: upsert route", zap.String("id", r.ID), zap.Error(err))
		}
	}

	a.mu.Lock()
	a.routeIDs[key] = newIDs
	a.mu.Unlock()

	a.logger.Info("k8s_ingress: synced ingress", zap.String("ingress", key), zap.Int("routes", len(routes)))
}

func (a *App) handleDelete(obj interface{}) {
	ing, ok := obj.(*networkingv1.Ingress)
	if !ok {
		return
	}
	key := ing.Namespace + "/" + ing.Name
	adm := newAdminClient(a.AdminAPI)

	a.mu.Lock()
	ids := a.routeIDs[key]
	delete(a.routeIDs, key)
	a.mu.Unlock()

	for _, id := range ids {
		if err := adm.deleteRoute(context.Background(), id); err != nil {
			a.logger.Warn("k8s_ingress: delete route", zap.String("id", id), zap.Error(err))
		}
	}
	a.logger.Info("k8s_ingress: removed ingress", zap.String("ingress", key))
}

func stringSet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// Interface assertions.
var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
