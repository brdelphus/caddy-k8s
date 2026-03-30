package k8singress

import (
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
)

// caddyRoute is the JSON representation of a single Caddy HTTP route.
type caddyRoute struct {
	ID       string        `json:"@id,omitempty"`
	Match    []caddyMatch  `json:"match,omitempty"`
	Handle   []interface{} `json:"handle"`
	Terminal bool          `json:"terminal,omitempty"`
}

type caddyMatch struct {
	Host     []string          `json:"host,omitempty"`
	Path     []string          `json:"path,omitempty"`
	RemoteIP *caddyRemoteIP    `json:"remote_ip,omitempty"`
	Not      []caddyMatchInner `json:"not,omitempty"`
}

type caddyMatchInner struct {
	RemoteIP *caddyRemoteIP `json:"remote_ip,omitempty"`
}

type caddyRemoteIP struct {
	Ranges []string `json:"ranges"`
}

// convertIngress converts a Kubernetes Ingress into one or more Caddy routes.
func convertIngress(ing *networkingv1.Ingress, sec SecurityConfig, ann ingressAnnotations) []caddyRoute {
	var routes []caddyRoute

	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}

		var pathRoutes []caddyRoute
		for i, p := range rule.HTTP.Paths {
			if p.Backend.Service == nil {
				continue
			}
			svc := p.Backend.Service.Name
			port := p.Backend.Service.Port.Number
			upstream := fmt.Sprintf("%s.%s.svc.cluster.local:%d", svc, ing.Namespace, port)

			pathMatch := caddyMatch{Path: convertPath(p.Path, p.PathType)}
			handlers := buildHandlers(upstream, sec, ann)
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

		// Prepend IP guard routes before path matching.
		guardRoutes := buildIPGuardRoutes(ann)
		allRoutes := append(guardRoutes, pathRoutes...)

		var handle []interface{}
		if len(allRoutes) == 1 && allRoutes[0].Match == nil && len(guardRoutes) == 0 {
			handle = allRoutes[0].Handle
		} else {
			handle = []interface{}{map[string]interface{}{
				"handler": "subroute",
				"routes":  allRoutes,
			}}
		}

		var match []caddyMatch
		if rule.Host != "" {
			match = []caddyMatch{{Host: []string{rule.Host}}}
		}

		routes = append(routes, caddyRoute{
			ID:       routeID(ing.Namespace, ing.Name, rule.Host, -1),
			Match:    match,
			Handle:   handle,
			Terminal: true,
		})
	}

	return routes
}

// httpRedirectRoutes returns 301 HTTP→HTTPS redirect routes for each host in
// the Ingress. These are injected into the HTTP (port 80) server.
func httpRedirectRoutes(ing *networkingv1.Ingress) []caddyRoute {
	var routes []caddyRoute
	for _, rule := range ing.Spec.Rules {
		if rule.Host == "" {
			continue
		}
		routes = append(routes, caddyRoute{
			ID:    routeID(ing.Namespace, ing.Name, rule.Host, -1) + "-http-redirect",
			Match: []caddyMatch{{Host: []string{rule.Host}}},
			Handle: []interface{}{
				map[string]interface{}{
					"handler":     "static_response",
					"status_code": 301,
					"headers": map[string][]string{
						"Location": {"https://{http.request.host}{http.request.uri}"},
					},
				},
			},
			Terminal: true,
		})
	}
	return routes
}

// buildIPGuardRoutes returns deny-first routes for whitelist and blocklist.
// Whitelist is evaluated before blocklist.
func buildIPGuardRoutes(ann ingressAnnotations) []caddyRoute {
	var guards []caddyRoute

	if len(ann.whitelist) > 0 {
		guards = append(guards, caddyRoute{
			Match: []caddyMatch{{
				Not: []caddyMatchInner{{
					RemoteIP: &caddyRemoteIP{Ranges: ann.whitelist},
				}},
			}},
			Handle:   []interface{}{map[string]interface{}{"handler": "static_response", "status_code": 403}},
			Terminal: true,
		})
	}

	if len(ann.blocklist) > 0 {
		guards = append(guards, caddyRoute{
			Match:    []caddyMatch{{RemoteIP: &caddyRemoteIP{Ranges: ann.blocklist}}},
			Handle:   []interface{}{map[string]interface{}{"handler": "static_response", "status_code": 403}},
			Terminal: true,
		})
	}

	return guards
}

// convertPath translates a Kubernetes path + pathType into Caddy path matchers.
func convertPath(path string, pt *networkingv1.PathType) []string {
	if path == "" || path == "/" {
		return nil
	}
	if pt != nil && *pt == networkingv1.PathTypeExact {
		return []string{path}
	}
	if strings.HasSuffix(path, "/") {
		return []string{path + "*"}
	}
	return []string{path, path + "/*"}
}

// buildHandlers assembles the handler chain for a route in execution order:
//  1. permanent-redirect (short-circuits — no other handlers run)
//  2. Basic auth
//  3. Body size limit
//  4. Security headers
//  5. Coraza WAF
//  6. reverse_proxy
func buildHandlers(upstream string, sec SecurityConfig, ann ingressAnnotations) []interface{} {
	// permanent-redirect replaces the entire handler chain with a 301.
	if ann.permanentRedirect != "" {
		return []interface{}{
			map[string]interface{}{
				"handler":     "static_response",
				"status_code": 301,
				"headers": map[string][]string{
					"Location": {ann.permanentRedirect},
				},
			},
		}
	}

	var handlers []interface{}

	if ann.basicAuth != nil {
		handlers = append(handlers, basicAuthHandler(ann.basicAuth))
	}

	if ann.proxy.maxBodySize > 0 {
		handlers = append(handlers, map[string]interface{}{
			"handler":  "request_body",
			"max_size": ann.proxy.maxBodySize,
		})
	}

	if sec.SecurityHeaders {
		handlers = append(handlers, securityHeadersHandler())
	}

	if sec.WAF {
		handlers = append(handlers, wafHandler(sec.WAFMode))
	}

	handlers = append(handlers, reverseProxyHandler(upstream, sec.InjectRealIP, ann.proxy))

	return handlers
}

// basicAuthHandler returns the Caddy http_basic authentication handler JSON.
func basicAuthHandler(cfg *basicAuthConfig) map[string]interface{} {
	accounts := make([]map[string]interface{}, 0, len(cfg.accounts))
	for _, a := range cfg.accounts {
		accounts = append(accounts, map[string]interface{}{
			"username": a.Username,
			"password": a.Password,
		})
	}
	return map[string]interface{}{
		"handler": "authentication",
		"providers": map[string]interface{}{
			"http_basic": map[string]interface{}{
				"realm":    cfg.realm,
				"accounts": accounts,
			},
		},
	}
}

// securityHeadersHandler returns the Caddy headers handler for common security
// response headers.
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

// reverseProxyHandler returns the Caddy reverse_proxy handler JSON, applying
// any per-Ingress proxy timeouts and real-IP header injection.
func reverseProxyHandler(upstream string, injectRealIP bool, proxy proxyConfig) map[string]interface{} {
	h := map[string]interface{}{
		"handler": "reverse_proxy",
		"upstreams": []map[string]interface{}{
			{"dial": upstream},
		},
	}

	// Transport — set when TLS, HTTP version, or timeouts are configured.
	transport := map[string]interface{}{"protocol": "http"}
	hasTransport := false

	if proxy.backendTLS {
		tls := map[string]interface{}{}
		if proxy.backendTLSInsecure {
			tls["insecure_skip_verify"] = true
		}
		transport["tls"] = tls
		hasTransport = true
	}
	if proxy.httpVersion != "" {
		transport["versions"] = []string{proxy.httpVersion}
		hasTransport = true
	}
	if proxy.readTimeout != "" {
		transport["response_header_timeout"] = proxy.readTimeout
		hasTransport = true
	}
	if proxy.sendTimeout != "" {
		transport["write_timeout"] = proxy.sendTimeout
		hasTransport = true
	}
	if proxy.connectTimeout != "" {
		transport["dial_timeout"] = proxy.connectTimeout
		hasTransport = true
	}
	if hasTransport {
		h["transport"] = transport
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

// routeID generates a stable Caddy route @id for a given Ingress host + path
// index. pathIdx = -1 is used for the parent host-level route.
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
