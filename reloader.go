package k8singress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

func init() {
	caddy.RegisterModule(&ConfigReloader{})
	httpcaddyfile.RegisterGlobalOption("k8s_config_reloader", parseReloaderOption)
}

// ConfigReloader is a Caddy app that watches a Kubernetes ConfigMap and
// reloads Caddy's configuration in-place when it changes.
// This replaces Stakater Reloader — no pod restart is ever needed.
//
// Caddyfile usage (global block):
//
//	{
//	    k8s_config_reloader {
//	        namespace  caddy
//	        configmap  caddy-config
//	        key        Caddyfile
//	    }
//	}
type ConfigReloader struct {
	// Namespace of the ConfigMap to watch.
	// Defaults to the pod's own namespace via the service-account projection.
	Namespace string `json:"namespace,omitempty"`

	// ConfigMap is the name of the ConfigMap to watch. Required.
	ConfigMap string `json:"configmap,omitempty"`

	// Key is the key in ConfigMap.data that holds the Caddyfile.
	// Default: "Caddyfile".
	Key string `json:"key,omitempty"`

	// AdminAPI is the Caddy admin API address. Default: localhost:2019.
	AdminAPI string `json:"admin_api,omitempty"`

	logger   *zap.Logger
	client   kubernetes.Interface
	stopCh   chan struct{}
	mu       sync.Mutex
	lastHash [32]byte
}

// CaddyModule returns the Caddy module info.
func (*ConfigReloader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "k8s_config_reloader",
		New: func() caddy.Module { return new(ConfigReloader) },
	}
}

// Provision sets defaults.
func (r *ConfigReloader) Provision(ctx caddy.Context) error {
	r.logger = ctx.Logger()
	if r.Key == "" {
		r.Key = "Caddyfile"
	}
	if r.AdminAPI == "" {
		r.AdminAPI = "localhost:2019"
	}
	if r.Namespace == "" {
		r.Namespace = reloaderPodNamespace()
	}
	r.stopCh = make(chan struct{})
	return nil
}

// Start launches the ConfigMap watcher.
func (r *ConfigReloader) Start() error {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("k8s_config_reloader: build kube config: %w", err)
		}
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("k8s_config_reloader: create k8s client: %w", err)
	}
	r.client = client

	factory := informers.NewSharedInformerFactoryWithOptions(
		client,
		10*time.Minute,
		informers.WithNamespace(r.Namespace),
	)
	cmInformer := factory.Core().V1().ConfigMaps().Informer()
	cmInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		// AddFunc fires on initial list sync — seed the hash, do NOT reload.
		AddFunc: func(obj interface{}) { r.handle(obj, false) },
		// UpdateFunc fires on real changes — reload if content differs.
		UpdateFunc: func(_, obj interface{}) { r.handle(obj, true) },
	})

	factory.Start(r.stopCh)
	if ok := cache.WaitForCacheSync(r.stopCh, cmInformer.HasSynced); !ok {
		return fmt.Errorf("k8s_config_reloader: cache sync timed out")
	}

	r.logger.Info("k8s_config_reloader: watching configmap",
		zap.String("namespace", r.Namespace),
		zap.String("configmap", r.ConfigMap),
		zap.String("key", r.Key),
	)
	return nil
}

// Stop shuts down the watcher goroutine.
func (r *ConfigReloader) Stop() error {
	close(r.stopCh)
	return nil
}

// handle processes a ConfigMap event.
func (r *ConfigReloader) handle(obj interface{}, isUpdate bool) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || cm.Name != r.ConfigMap {
		return
	}
	content, ok := cm.Data[r.Key]
	if !ok {
		r.logger.Warn("k8s_config_reloader: key not found in configmap",
			zap.String("configmap", r.ConfigMap),
			zap.String("key", r.Key),
		)
		return
	}

	h := sha256.Sum256([]byte(content))
	r.mu.Lock()
	unchanged := h == r.lastHash
	r.lastHash = h
	r.mu.Unlock()

	if !isUpdate {
		// Startup sync: seed the hash so we detect future changes.
		r.logger.Debug("k8s_config_reloader: seeded initial config hash",
			zap.String("configmap", r.ConfigMap))
		return
	}
	if unchanged {
		return
	}

	r.logger.Info("k8s_config_reloader: configmap changed — reloading caddy",
		zap.String("configmap", r.ConfigMap))
	if err := r.reload(content); err != nil {
		r.logger.Error("k8s_config_reloader: reload failed", zap.Error(err))
	}
}

// reload POSTs the new Caddyfile to Caddy's /load admin endpoint.
func (r *ConfigReloader) reload(caddyfileContent string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	url := "http://" + r.AdminAPI + "/load"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		bytes.NewBufferString(caddyfileContent))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/caddyfile")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST /load: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /load returned %s", resp.Status)
	}
	r.logger.Info("k8s_config_reloader: caddy reloaded successfully")
	return nil
}

// ── Caddyfile parsing ─────────────────────────────────────────────────────────

func parseReloaderOption(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	app := new(ConfigReloader)
	if err := app.UnmarshalCaddyfile(d); err != nil {
		return nil, err
	}
	return httpcaddyfile.App{
		Name:  "k8s_config_reloader",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

// UnmarshalCaddyfile reads the k8s_config_reloader global block.
func (r *ConfigReloader) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "namespace":
				if !d.NextArg() {
					return d.ArgErr()
				}
				r.Namespace = d.Val()
			case "configmap":
				if !d.NextArg() {
					return d.ArgErr()
				}
				r.ConfigMap = d.Val()
			case "key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				r.Key = d.Val()
			case "admin_api":
				if !d.NextArg() {
					return d.ArgErr()
				}
				r.AdminAPI = d.Val()
			default:
				return d.Errf("unknown k8s_config_reloader option: %s", d.Val())
			}
		}
	}
	if r.ConfigMap == "" {
		return d.Err("k8s_config_reloader: configmap name is required")
	}
	return nil
}

// reloaderPodNamespace returns the current pod's namespace by reading the
// service-account namespace projection mounted by Kubernetes.
func reloaderPodNamespace() string {
	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "default"
	}
	return string(bytes.TrimSpace(b))
}
