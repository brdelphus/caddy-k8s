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

// tlsAutomationPolicy is a Caddy TLS automation policy pushed to the admin API.
type tlsAutomationPolicy struct {
	ID       string        `json:"@id"`
	Subjects []string      `json:"subjects"`
	Issuers  []interface{} `json:"issuers,omitempty"`
	OnDemand bool          `json:"on_demand,omitempty"`
}

// acmeIssuer is a Caddy ACME certificate issuer config.
type acmeIssuer struct {
	Module          string               `json:"module"`
	CA              string               `json:"ca,omitempty"`
	ExternalAccount *acmeExternalAccount `json:"external_account,omitempty"`
}

type acmeExternalAccount struct {
	KeyID  string `json:"key_id"`
	MACKey string `json:"mac_key"`
}

// TLSPolicyManager creates and removes per-Ingress CertMagic automation
// policies in Caddy's TLS app. Each policy is identified by a stable @id
// derived from the Ingress namespace/name so it can be updated or deleted
// individually without affecting other policies or the global default.
type TLSPolicyManager struct {
	client   kubernetes.Interface
	adminAPI string
	logger   *zap.Logger
}

// NewTLSPolicyManager creates a new TLSPolicyManager.
func NewTLSPolicyManager(client kubernetes.Interface, adminAPI string, logger *zap.Logger) *TLSPolicyManager {
	return &TLSPolicyManager{
		client:   client,
		adminAPI: adminAPI,
		logger:   logger,
	}
}

// Sync creates or updates the TLS automation policy for an Ingress.
// Only called when caddy.ingress/tls is "certmagic" and at least one of
// tls-ondemand or tls-ca is set.
func (m *TLSPolicyManager) Sync(ctx context.Context, ing *networkingv1.Ingress, ann ingressAnnotations) error {
	hosts := tlsHosts(ing)
	if len(hosts) == 0 {
		return nil
	}

	policy := tlsAutomationPolicy{
		ID:       tlsPolicyID(ing),
		Subjects: hosts,
		OnDemand: ann.tlsOnDemand,
	}

	if ann.tlsCA != "" {
		issuer := acmeIssuer{
			Module: "acme",
			CA:     ann.tlsCA,
		}

		if ann.tlsCASecret != "" {
			eab, err := m.readEABSecret(ctx, ing.Namespace, ann.tlsCASecret)
			if err != nil {
				return fmt.Errorf("read EAB secret %s/%s: %w", ing.Namespace, ann.tlsCASecret, err)
			}
			issuer.ExternalAccount = eab
		}

		policy.Issuers = []interface{}{issuer}
	}

	adm := newAdminClient(m.adminAPI)
	if err := adm.upsertTLSPolicy(ctx, policy); err != nil {
		return fmt.Errorf("upsert TLS policy: %w", err)
	}

	m.logger.Info("k8s_ingress: synced TLS automation policy",
		zap.String("ingress", ing.Namespace+"/"+ing.Name),
		zap.Strings("hosts", hosts),
		zap.Bool("on_demand", ann.tlsOnDemand),
		zap.String("ca", ann.tlsCA),
	)
	return nil
}

// Remove deletes the TLS automation policy for an Ingress if one exists.
func (m *TLSPolicyManager) Remove(ctx context.Context, ing *networkingv1.Ingress) error {
	id := tlsPolicyID(ing)
	adm := newAdminClient(m.adminAPI)
	if err := adm.deleteTLSPolicy(ctx, id); err != nil {
		return fmt.Errorf("delete TLS policy: %w", err)
	}
	m.logger.Info("k8s_ingress: removed TLS automation policy",
		zap.String("ingress", ing.Namespace+"/"+ing.Name),
	)
	return nil
}

// readEABSecret reads EAB credentials from a Kubernetes Secret.
// The Secret must have keys "key_id" and "mac_key".
func (m *TLSPolicyManager) readEABSecret(ctx context.Context, namespace, name string) (*acmeExternalAccount, error) {
	secret, err := m.client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	keyID := strings.TrimSpace(string(secret.Data["key_id"]))
	macKey := strings.TrimSpace(string(secret.Data["mac_key"]))

	if keyID == "" || macKey == "" {
		return nil, fmt.Errorf("secret %s/%s must have non-empty keys 'key_id' and 'mac_key'", namespace, name)
	}

	return &acmeExternalAccount{
		KeyID:  keyID,
		MACKey: macKey,
	}, nil
}

// tlsPolicyID returns a stable Caddy @id for the TLS automation policy of
// the given Ingress.
func tlsPolicyID(ing *networkingv1.Ingress) string {
	return "k8s-tls-policy-" + ing.Namespace + "-" + ing.Name
}

// tlsHosts collects all unique hostnames from the Ingress spec.tls blocks.
func tlsHosts(ing *networkingv1.Ingress) []string {
	seen := make(map[string]bool)
	var hosts []string
	for _, tls := range ing.Spec.TLS {
		for _, h := range tls.Hosts {
			if h != "" && !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	return hosts
}
