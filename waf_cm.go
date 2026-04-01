package k8singress

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const wafCMDirectivesKey = "directives"

// defaultWAFDirectives is the content of a freshly-created per-Ingress WAF
// ConfigMap. Operators edit this file to customise rules for the Ingress.
// Directives are injected after the OWASP CRS Includes and before
// SecRuleEngine, so they operate on already-defined rules.
const defaultWAFDirectives = `# Per-Ingress Coraza WAF directives.
# Lines starting with '#' and blank lines are ignored by caddy-k8s.
#
# Directives here are appended after the OWASP CRS Includes, so you can:
#   Disable a rule:           SecRuleRemoveById 920350
#   Restrict a rule's target: SecRuleUpdateTargetById 942100 "!ARGS:search"
#   Add a custom rule:        SecRule ARGS "@contains badword" "id:1001,phase:2,deny,status:400"
#
# SecRuleEngine is controlled by the caddy.ingress/waf annotation — do not set it here.
`

// wafConfigMapName returns the conventional ConfigMap name for an Ingress WAF
// rules ConfigMap: <ingress-name>-waf-rules.
func wafConfigMapName(ingName string) string {
	return ingName + "-waf-rules"
}

// ensureWAFConfigMap creates the per-Ingress WAF ConfigMap when the Ingress
// has caddy.ingress/waf set to "on" or "detection" and no
// caddy.ingress/waf-rules-configmap annotation is present yet. It patches the
// annotation onto the Ingress for persistence across restarts, then returns the
// ConfigMap name so the caller can inject it into the in-memory Ingress object
// for the current sync cycle.
//
// Returns ("", nil) when the Ingress does not have WAF enabled or already has
// a waf-rules-configmap annotation.
func (a *App) ensureWAFConfigMap(ctx context.Context, ing *networkingv1.Ingress) (string, error) {
	wafVal := strings.ToLower(strings.TrimSpace(ing.Annotations[annotationWAF]))
	if wafVal != "on" && wafVal != "detection" {
		return "", nil
	}
	// Already annotated — nothing to do.
	if existing := strings.TrimSpace(ing.Annotations[annotationWAFRulesConfigMap]); existing != "" {
		return existing, nil
	}

	cmName := wafConfigMapName(ing.Name)

	if err := createWAFConfigMapIfAbsent(ctx, a.client, ing.Namespace, cmName, ing); err != nil {
		return "", fmt.Errorf("create waf configmap %s/%s: %w", ing.Namespace, cmName, err)
	}

	// Patch the Ingress annotation so future syncs load the CM automatically.
	patch := fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, annotationWAFRulesConfigMap, cmName)
	if _, err := a.client.NetworkingV1().Ingresses(ing.Namespace).Patch(
		ctx, ing.Name, types.MergePatchType, []byte(patch), metav1.PatchOptions{},
	); err != nil {
		// Non-fatal: we still return the CM name so the current sync works.
		a.logger.Warn("k8s_ingress: failed to patch waf-rules-configmap annotation — will retry on next sync",
			zap.String("ingress", ing.Namespace+"/"+ing.Name),
			zap.Error(err),
		)
	}

	a.logger.Info("k8s_ingress: created WAF rules configmap",
		zap.String("ingress", ing.Namespace+"/"+ing.Name),
		zap.String("configmap", ing.Namespace+"/"+cmName),
	)
	return cmName, nil
}

// createWAFConfigMapIfAbsent creates the ConfigMap with default directives and
// an OwnerReference to the Ingress (so K8s GC deletes it when the Ingress is
// removed). A no-op if the ConfigMap already exists.
func createWAFConfigMapIfAbsent(ctx context.Context, client kubernetes.Interface, namespace, cmName string, ing *networkingv1.Ingress) error {
	_, err := client.CoreV1().ConfigMaps(namespace).Get(ctx, cmName, metav1.GetOptions{})
	if err == nil {
		return nil // already exists
	}
	if !k8serrors.IsNotFound(err) {
		return fmt.Errorf("get configmap: %w", err)
	}

	controller := false
	blockOwnerDeletion := false
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "caddy-k8s",
				"caddy.ingress/ingress":        ing.Name,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         "networking.k8s.io/v1",
				Kind:               "Ingress",
				Name:               ing.Name,
				UID:                ing.UID,
				Controller:         &controller,
				BlockOwnerDeletion: &blockOwnerDeletion,
			}},
		},
		Data: map[string]string{
			wafCMDirectivesKey: defaultWAFDirectives,
		},
	}

	_, err = client.CoreV1().ConfigMaps(namespace).Create(ctx, cm, metav1.CreateOptions{})
	if k8serrors.IsAlreadyExists(err) {
		return nil // race — another goroutine created it first
	}
	return err
}
