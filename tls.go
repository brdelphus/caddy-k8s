package k8singress

import (
	"context"
	"sync"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// TLSManager watches TLS secrets referenced by Ingress spec.tls and loads
// them into Caddy via the admin API.
type TLSManager struct {
	client   kubernetes.Interface
	adminAPI string
	logger   *zap.Logger

	// managedCerts tracks which secrets are currently loaded into Caddy.
	// Key: "namespace/secretName"
	managedCerts map[string]*tlsCert
	// secretToIngress maps "namespace/secretName" to the set of Ingress keys
	// ("namespace/name") that reference it.
	secretToIngress map[string]map[string]bool
	mu              sync.RWMutex

	stopCh chan struct{}
}

// tlsCert holds the certificate data from a Kubernetes TLS secret.
type tlsCert struct {
	secretNamespace string
	secretName      string
	hosts           []string
	cert            []byte // PEM-encoded certificate
	key             []byte // PEM-encoded private key
}

// NewTLSManager creates a new TLS manager.
func NewTLSManager(client kubernetes.Interface, adminAPI string, logger *zap.Logger) *TLSManager {
	return &TLSManager{
		client:          client,
		adminAPI:        adminAPI,
		logger:          logger,
		managedCerts:    make(map[string]*tlsCert),
		secretToIngress: make(map[string]map[string]bool),
		stopCh:          make(chan struct{}),
	}
}

// LoadFromIngress processes spec.tls entries and loads referenced secrets.
func (m *TLSManager) LoadFromIngress(ctx context.Context, ing *networkingv1.Ingress) error {
	if len(ing.Spec.TLS) == 0 {
		return nil
	}

	ingressKey := ing.Namespace + "/" + ing.Name
	adm := newAdminClient(m.adminAPI)

	for _, tls := range ing.Spec.TLS {
		if tls.SecretName == "" {
			continue
		}

		secretKey := ing.Namespace + "/" + tls.SecretName
		m.logger.Debug("k8s_ingress: processing TLS secret",
			zap.String("ingress", ingressKey),
			zap.String("secret", secretKey),
			zap.Strings("hosts", tls.Hosts),
		)

		// Track that this Ingress references this secret.
		m.mu.Lock()
		if m.secretToIngress[secretKey] == nil {
			m.secretToIngress[secretKey] = make(map[string]bool)
		}
		m.secretToIngress[secretKey][ingressKey] = true
		m.mu.Unlock()

		// Load the secret.
		secret, err := m.client.CoreV1().Secrets(ing.Namespace).Get(ctx, tls.SecretName, metav1.GetOptions{})
		if err != nil {
			m.logger.Warn("k8s_ingress: failed to load TLS secret",
				zap.String("ingress", ingressKey),
				zap.String("secret", secretKey),
				zap.Error(err),
			)
			continue
		}

		if secret.Type != corev1.SecretTypeTLS {
			m.logger.Warn("k8s_ingress: secret is not a TLS secret",
				zap.String("ingress", ingressKey),
				zap.String("secret", secretKey),
				zap.String("type", string(secret.Type)),
			)
			continue
		}

		cert := &tlsCert{
			secretNamespace: ing.Namespace,
			secretName:      tls.SecretName,
			hosts:           tls.Hosts,
			cert:            secret.Data[corev1.TLSCertKey],
			key:             secret.Data[corev1.TLSPrivateKeyKey],
		}

		if len(cert.cert) == 0 || len(cert.key) == 0 {
			m.logger.Warn("k8s_ingress: TLS secret missing cert or key data",
				zap.String("ingress", ingressKey),
				zap.String("secret", secretKey),
			)
			continue
		}

		// Push to Caddy.
		if err := m.pushCertToCaddy(ctx, adm, cert); err != nil {
			m.logger.Error("k8s_ingress: failed to push TLS cert to Caddy",
				zap.String("ingress", ingressKey),
				zap.String("secret", secretKey),
				zap.Error(err),
			)
			continue
		}

		m.mu.Lock()
		m.managedCerts[secretKey] = cert
		m.mu.Unlock()

		m.logger.Info("k8s_ingress: loaded TLS certificate",
			zap.String("ingress", ingressKey),
			zap.String("secret", secretKey),
			zap.Strings("hosts", tls.Hosts),
		)
	}

	return nil
}

// RemoveFromIngress cleans up TLS certificates when an Ingress is deleted.
func (m *TLSManager) RemoveFromIngress(ing *networkingv1.Ingress) {
	ingressKey := ing.Namespace + "/" + ing.Name

	for _, tls := range ing.Spec.TLS {
		if tls.SecretName == "" {
			continue
		}
		secretKey := ing.Namespace + "/" + tls.SecretName

		m.mu.Lock()
		if refs := m.secretToIngress[secretKey]; refs != nil {
			delete(refs, ingressKey)
			// If no more Ingresses reference this secret, we could remove it
			// from Caddy. However, Caddy doesn't have a clean way to unload
			// a specific certificate by tag, so we leave it loaded.
			// It will be garbage-collected on Caddy restart.
			if len(refs) == 0 {
				delete(m.secretToIngress, secretKey)
				delete(m.managedCerts, secretKey)
			}
		}
		m.mu.Unlock()
	}
}

// pushCertToCaddy loads a certificate into Caddy via the admin API.
func (m *TLSManager) pushCertToCaddy(ctx context.Context, adm *adminClient, cert *tlsCert) error {
	// POST /config/apps/tls/certificates with load_pem array.
	// The certificate and key must be PEM-encoded strings with armor.
	payload := map[string]interface{}{
		"load_pem": []map[string]interface{}{
			{
				"certificate": string(cert.cert),
				"key":         string(cert.key),
				"tags":        []string{"k8s-ingress", cert.secretNamespace + "/" + cert.secretName},
			},
		},
	}

	return adm.postJSON(ctx, "/config/apps/tls/certificates", payload)
}

// WatchSecrets starts an informer to watch TLS secrets and reload them when updated.
func (m *TLSManager) WatchSecrets(ctx context.Context) {
	m.logger.Info("k8s_ingress: starting TLS secret watcher")

	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				options.FieldSelector = "type=kubernetes.io/tls"
				return m.client.CoreV1().Secrets("").List(ctx, options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				options.FieldSelector = "type=kubernetes.io/tls"
				return m.client.CoreV1().Secrets("").Watch(ctx, options)
			},
		},
		&corev1.Secret{},
		0,
		cache.Indexers{},
	)

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new interface{}) {
			secret := new.(*corev1.Secret)
			secretKey := secret.Namespace + "/" + secret.Name

			m.mu.RLock()
			_, managed := m.managedCerts[secretKey]
			m.mu.RUnlock()

			if managed {
				m.reloadSecret(ctx, secret)
			}
		},
	})

	go informer.Run(m.stopCh)
}

// reloadSecret reloads a secret that has been updated.
func (m *TLSManager) reloadSecret(ctx context.Context, secret *corev1.Secret) {
	secretKey := secret.Namespace + "/" + secret.Name
	adm := newAdminClient(m.adminAPI)

	m.mu.RLock()
	existing := m.managedCerts[secretKey]
	m.mu.RUnlock()

	if existing == nil {
		return
	}

	cert := &tlsCert{
		secretNamespace: secret.Namespace,
		secretName:      secret.Name,
		hosts:           existing.hosts,
		cert:            secret.Data[corev1.TLSCertKey],
		key:             secret.Data[corev1.TLSPrivateKeyKey],
	}

	if len(cert.cert) == 0 || len(cert.key) == 0 {
		m.logger.Warn("k8s_ingress: updated TLS secret missing cert or key data",
			zap.String("secret", secretKey),
		)
		return
	}

	if err := m.pushCertToCaddy(ctx, adm, cert); err != nil {
		m.logger.Error("k8s_ingress: failed to reload TLS cert",
			zap.String("secret", secretKey),
			zap.Error(err),
		)
		return
	}

	m.mu.Lock()
	m.managedCerts[secretKey] = cert
	m.mu.Unlock()

	m.logger.Info("k8s_ingress: reloaded TLS certificate",
		zap.String("secret", secretKey),
		zap.Strings("hosts", cert.hosts),
	)
}

// Stop shuts down the TLS manager.
func (m *TLSManager) Stop() {
	close(m.stopCh)
}

// ManagedHosts returns all hosts that have certificates loaded from spec.tls.
// This can be used to skip ACME for these hosts.
func (m *TLSManager) ManagedHosts() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hostSet := make(map[string]bool)
	for _, cert := range m.managedCerts {
		for _, h := range cert.hosts {
			hostSet[h] = true
		}
	}

	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	return hosts
}
