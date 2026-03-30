package k8singress

import (
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
)

// caddyRoute is the JSON representation of a single Caddy HTTP route.
// Fields must match Caddy's admin API JSON schema exactly.
type caddyRoute struct {
	ID       string        `json:"@id,omitempty"`
	Match    []caddyMatch  `json:"match,omitempty"`
	Handle   []interface{} `json:"handle"`
	Terminal bool          `json:"terminal,omitempty"`
}

type caddyMatch struct {
	Host []string `json:"host,omitempty"`
	Path []string `json:"path,omitempty"`
}

// convertIngress converts a Kubernetes Ingress into one or more Caddy routes.
// Each host in the Ingress rules becomes a separate route with a subroute
// handler for per-path dispatch.
func convertIngress(ing *networkingv1.Ingress, sec SecurityConfig) []caddyRoute {
	var routes []caddyRoute

	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}

		// Build per-path subroutes.
		var pathRoutes []caddyRoute
		for i, p := range rule.HTTP.Paths {
			if p.Backend.Service == nil {
				continue
			}
			svc := p.Backend.Service.Name
			port := p.Backend.Service.Port.Number
			upstream := fmt.Sprintf("%s.%s.svc.cluster.local:%d", svc, ing.Namespace, port)

			pathMatch := caddyMatch{
				Path: convertPath(p.Path, p.PathType),
			}

			handlers := buildHandlers(upstream, sec)

			// Assign a stable ID so we can upsert/delete individual paths.
			pathRouteID := routeID(ing.Namespace, ing.Name, rule.Host, i)

			var match []caddyMatch
			if len(pathMatch.Path) > 0 {
				match = []caddyMatch{pathMatch}
			}

			pathRoutes = append(pathRoutes, caddyRoute{
				ID:     pathRouteID,
				Match:  match,
				Handle: handlers,
			})
		}

		if len(pathRoutes) == 0 {
			continue
		}

		// If there's only one path and no host, emit a flat route.
		// Otherwise wrap in subroute under the host matcher.
		var handle []interface{}
		if len(pathRoutes) == 1 && pathRoutes[0].Match == nil {
			handle = pathRoutes[0].Handle
		} else {
			subroute := map[string]interface{}{
				"handler": "subroute",
				"routes":  pathRoutes,
			}
			handle = []interface{}{subroute}
		}

		var match []caddyMatch
		if rule.Host != "" {
			match = []caddyMatch{{Host: []string{rule.Host}}}
		}

		// Use the first path route's ID as the parent route ID so that
		// the admin client can upsert/delete it via @id.
		id := routeID(ing.Namespace, ing.Name, rule.Host, -1)

		routes = append(routes, caddyRoute{
			ID:       id,
			Match:    match,
			Handle:   handle,
			Terminal: true,
		})
	}

	return routes
}

// convertPath translates a Kubernetes Ingress path + pathType into Caddy path
// matcher strings.
func convertPath(path string, pt *networkingv1.PathType) []string {
	if path == "" || path == "/" {
		return nil // match all paths — no path constraint needed
	}

	if pt != nil && *pt == networkingv1.PathTypeExact {
		return []string{path}
	}

	// Prefix (and ImplementationSpecific treated as Prefix):
	// "/api" should match "/api" and "/api/anything" but NOT "/apifoo".
	if strings.HasSuffix(path, "/") {
		// "/api/" → match "/api/*"
		return []string{path + "*"}
	}
	// "/api" → match "/api" exactly and "/api/*"
	return []string{path, path + "/*"}
}

// buildHandlers assembles the ordered handler chain for a route:
//  1. Security headers (if enabled)
//  2. Coraza WAF (if enabled)
//  3. reverse_proxy to upstream
func buildHandlers(upstream string, sec SecurityConfig) []interface{} {
	var handlers []interface{}

	if sec.SecurityHeaders {
		handlers = append(handlers, securityHeadersHandler())
	}

	if sec.WAF {
		handlers = append(handlers, wafHandler(sec.WAFMode))
	}

	handlers = append(handlers, reverseProxyHandler(upstream, sec.InjectRealIP))

	return handlers
}

// securityHeadersHandler returns the Caddy headers handler JSON that sets
// common security response headers.
func securityHeadersHandler() map[string]interface{} {
	return map[string]interface{}{
		"handler": "headers",
		"response": map[string]interface{}{
			"set": map[string][]string{
				"Strict-Transport-Security": {"max-age=31536000; includeSubDomains"},
				"X-Content-Type-Options":    {"nosniff"},
				"X-Frame-Options":           {"SAMEORIGIN"},
				"Referrer-Policy":           {"strict-origin-when-cross-origin"},
			},
			"delete": []string{"Server"},
		},
	}
}

// wafHandler returns the Coraza WAF handler JSON.
// Requires coraza-caddy compiled into the Caddy binary.
func wafHandler(mode string) map[string]interface{} {
	ruleEngine := "DetectionOnly"
	if strings.EqualFold(mode, "On") {
		ruleEngine = "On"
	}
	return map[string]interface{}{
		"handler": "waf",
		"directives": []string{
			fmt.Sprintf("SecRuleEngine %s", ruleEngine),
			"SecRequestBodyAccess On",
			"SecResponseBodyAccess Off",
			"SecRequestBodyLimit 13107200",
		},
		"load_owasp_crs": true,
	}
}

// reverseProxyHandler returns the Caddy reverse_proxy handler JSON.
func reverseProxyHandler(upstream string, injectRealIP bool) map[string]interface{} {
	h := map[string]interface{}{
		"handler": "reverse_proxy",
		"upstreams": []map[string]interface{}{
			{"dial": upstream},
		},
	}

	if injectRealIP {
		h["headers"] = map[string]interface{}{
			"request": map[string]interface{}{
				"set": map[string][]string{
					"X-Real-IP":         {"{client_ip}"},
					"X-Forwarded-For":   {"{client_ip}"},
					"X-Forwarded-Proto": {"https"},
					"X-Forwarded-Host":  {"{http.request.host}"},
				},
			},
		}
	}

	return h
}

// routeID generates a stable, unique Caddy route @id for a given Ingress
// host + path index. Use pathIdx = -1 for the parent (host-level) route.
func routeID(namespace, name, host string, pathIdx int) string {
	h := strings.ReplaceAll(host, ".", "-")
	h = strings.ReplaceAll(h, "*", "wildcard")
	if h == "" {
		h = "any"
	}
	if pathIdx < 0 {
		return fmt.Sprintf("caddy-k8s-%s-%s-%s", namespace, name, h)
	}
	return fmt.Sprintf("caddy-k8s-%s-%s-%s-p%d", namespace, name, h, pathIdx)
}
