package k8singress

import (
	"fmt"
	"strconv"
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
	Host     []string            `json:"host,omitempty"`
	Path     []string            `json:"path,omitempty"`
	Method   []string            `json:"method,omitempty"`
	Headers  map[string][]string `json:"header,omitempty"` // "header" is the Caddy matcher module key
	RemoteIP *caddyRemoteIP      `json:"remote_ip,omitempty"`
	Not      []caddyMatchInner   `json:"not,omitempty"`
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
			handlers := buildHandlers(upstream, sec, ann, len(ing.Spec.TLS) == 0)
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

		// Prepend IP guards then CORS preflight before path routes.
		guardRoutes := buildIPGuardRoutes(ann)
		var preflightRoutes []caddyRoute
		if ann.cors != nil {
			preflightRoutes = append(preflightRoutes, corsPreflightRoute(ann.cors))
		}
		allRoutes := append(guardRoutes, append(preflightRoutes, pathRoutes...)...)

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
		if rule.Host != "" || len(ann.serverAliases) > 0 {
			hosts := make([]string, 0, 1+len(ann.serverAliases))
			if rule.Host != "" {
				hosts = append(hosts, rule.Host)
			}
			hosts = append(hosts, ann.serverAliases...)
			match = []caddyMatch{{Host: hosts}}
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

// buildHandlers assembles the handler chain for a route. For multi-origin CORS,
// it wraps the core chain in a per-origin subroute to safely echo the matched
// origin back. All other cases produce a flat chain.
//
// Execution order:
//  1. permanent/temporal redirect  (short-circuits)
//  2. CORS response headers        (prepended so error responses also carry them)
//  3. Basic auth
//  4. Body size limit
//  5. Rate limiting                (early reject before WAF)
//  6. URI rewrite
//  7. Security headers
//  8. Coraza WAF
//  9. Authorization policy         (caddy-security or any custom handler)
// 10. reverse_proxy
func buildHandlers(upstream string, sec SecurityConfig, ann ingressAnnotations, plainHTTP bool) []interface{} {
	// Redirect annotations replace the entire handler chain.
	if ann.permanentRedirect != "" || ann.temporalRedirect != "" {
		url := ann.permanentRedirect
		code := 301
		if ann.temporalRedirect != "" {
			url = ann.temporalRedirect
			code = 302
		}
		if ann.redirectCode > 0 {
			code = ann.redirectCode
		}
		return []interface{}{
			map[string]interface{}{
				"handler":     "static_response",
				"status_code": code,
				"headers": map[string][]string{
					"Location": {url},
				},
			},
		}
	}

	cors := ann.cors
	if cors != nil && len(cors.origins) > 1 {
		// Multiple specific origins: generate a subroute so we only echo back an
		// origin that is in the allowed list. Uses {http.request.header.Origin}
		// as the header value exclusively within the matched branch.
		withCORS := buildCoreHandlers(upstream, sec, ann, plainHTTP, true, true)
		withoutCORS := buildCoreHandlers(upstream, sec, ann, plainHTTP, false, false)
		return []interface{}{map[string]interface{}{
			"handler": "subroute",
			"routes": []caddyRoute{
				{
					Match:    []caddyMatch{{Headers: map[string][]string{"Origin": cors.origins}}},
					Handle:   withCORS,
					Terminal: true,
				},
				{
					Handle:   withoutCORS,
					Terminal: true,
				},
			},
		}}
	}

	return buildCoreHandlers(upstream, sec, ann, plainHTTP, cors != nil, false)
}

// buildCoreHandlers builds the flat handler chain.
// withCORS: prepend CORS response headers handler.
// dynamic: use {http.request.header.Origin} as the Allow-Origin value instead
//
//	of the literal origin (safe only within an origin-matched subroute branch).
func buildCoreHandlers(upstream string, sec SecurityConfig, ann ingressAnnotations, plainHTTP bool, withCORS bool, dynamic bool) []interface{} {
	var handlers []interface{}

	if withCORS && ann.cors != nil {
		handlers = append(handlers, corsResponseHandler(ann.cors, dynamic))
	}

	if ann.basicAuth != nil {
		handlers = append(handlers, basicAuthHandler(ann.basicAuth))
	}

	if ann.proxy.maxBodySize > 0 {
		handlers = append(handlers, map[string]interface{}{
			"handler":  "request_body",
			"max_size": ann.proxy.maxBodySize,
		})
	}

	if ann.limitRPS > 0 {
		handlers = append(handlers, rateLimitHandler(ann.namespace, ann.name, ann.limitRPS))
	}

	if ann.rewriteTarget != "" {
		handlers = append(handlers, map[string]interface{}{
			"handler": "rewrite",
			"uri":     ann.rewriteTarget,
		})
	}

	// Skip security headers on plain HTTP routes — HSTS on HTTP is incorrect and
	// ignored by browsers; the other headers are irrelevant for internal services.
	if sec.SecurityHeaders && !plainHTTP {
		handlers = append(handlers, securityHeadersHandler())
	}

	// Per-Ingress response headers (set/delete). Runs after security headers so
	// it can override them if needed.
	if !ann.responseHeaders.empty() {
		handlers = append(handlers, responseHeadersHandler(ann.responseHeaders))
	}

	// WAF: per-route annotation overrides the global SecurityConfig setting.
	wafEnabled := sec.WAF
	wafMode := sec.WAFMode
	if ann.wafOverride != nil {
		wafEnabled = *ann.wafOverride
		if ann.wafModeOverride != "" {
			wafMode = ann.wafModeOverride
		}
	}
	if wafEnabled {
		handlers = append(handlers, wafHandler(wafMode, ann.wafDirectives))
	}

	if ann.authPolicyHandler != nil {
		handlers = append(handlers, ann.authPolicyHandler)
	}

	handlers = append(handlers, reverseProxyHandler(upstream, sec.InjectRealIP, ann.proxy, plainHTTP, ann.requestHeaders))

	return handlers
}

// corsPreflightRoute returns a terminal route that handles OPTIONS preflight
// requests. For specific origins the route additionally matches the Origin
// header so unrecognised origins fall through to a plain 204 (no CORS headers).
func corsPreflightRoute(cors *corsConfig) caddyRoute {
	var match caddyMatch
	if cors.isWildcard() {
		match = caddyMatch{Method: []string{"OPTIONS"}}
	} else {
		match = caddyMatch{
			Method:  []string{"OPTIONS"},
			Headers: map[string][]string{"Origin": cors.origins},
		}
	}
	dynamic := len(cors.origins) > 1
	return caddyRoute{
		Match: []caddyMatch{match},
		Handle: []interface{}{
			corsResponseHandler(cors, dynamic),
			map[string]interface{}{"handler": "static_response", "status_code": 204},
		},
		Terminal: true,
	}
}

// corsResponseHandler wraps buildCORSResponseHeaders in a Caddy headers handler.
func corsResponseHandler(cors *corsConfig, dynamic bool) map[string]interface{} {
	return map[string]interface{}{
		"handler":  "headers",
		"response": map[string]interface{}{"set": buildCORSResponseHeaders(cors, dynamic)},
	}
}

// buildCORSResponseHeaders assembles the full set of CORS response headers.
// dynamic=true substitutes {http.request.header.Origin} for the Allow-Origin
// value — only use this inside a route that has already validated the origin.
func buildCORSResponseHeaders(cors *corsConfig, dynamic bool) map[string][]string {
	var origin string
	if dynamic {
		origin = "{http.request.header.Origin}"
	} else {
		origin = cors.origins[0] // "*" or a single specific origin
	}

	h := map[string][]string{
		"Access-Control-Allow-Origin": {origin},
	}
	// Vary: Origin is required for caches whenever the response differs by origin.
	if origin != "*" {
		h["Vary"] = []string{"Origin"}
	}
	if cors.allowMethods != "" {
		h["Access-Control-Allow-Methods"] = []string{cors.allowMethods}
	}
	if cors.allowHeaders != "" {
		h["Access-Control-Allow-Headers"] = []string{cors.allowHeaders}
	}
	if cors.exposeHeaders != "" {
		h["Access-Control-Expose-Headers"] = []string{cors.exposeHeaders}
	}
	if cors.allowCreds {
		h["Access-Control-Allow-Credentials"] = []string{"true"}
	}
	if cors.maxAge > 0 {
		h["Access-Control-Max-Age"] = []string{strconv.Itoa(cors.maxAge)}
	}
	return h
}

// rateLimitHandler returns a caddy-ratelimit handler that limits requests per
// second from each client IP. Zone name is derived from the Ingress namespace
// and name to avoid collisions between routes.
func rateLimitHandler(namespace, name string, rps int) map[string]interface{} {
	zoneName := fmt.Sprintf("caddy-k8s-%s-%s", namespace, name)
	return map[string]interface{}{
		"handler": "rate_limit",
		"rate_limits": map[string]interface{}{
			zoneName: map[string]interface{}{
				"key":        "{client_ip}",
				"window":     "1s",
				"max_events": rps,
			},
		},
	}
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

// responseHeadersHandler returns a Caddy headers handler that sets and/or
// deletes response headers as specified by the per-Ingress annotation.
func responseHeadersHandler(cfg headerConfig) map[string]interface{} {
	resp := map[string]interface{}{}
	if len(cfg.set) > 0 {
		set := make(map[string][]string, len(cfg.set))
		for k, v := range cfg.set {
			set[k] = []string{v}
		}
		resp["set"] = set
	}
	if len(cfg.delete) > 0 {
		resp["delete"] = cfg.delete
	}
	return map[string]interface{}{
		"handler":  "headers",
		"response": resp,
	}
}

// wafHandler returns the Coraza WAF handler JSON.
//
// Include ordering matters: @coraza.conf-recommended sets SecRuleEngine
// DetectionOnly; @crs-setup and @owasp_crs must be included before the
// SecRuleEngine override so the final value is ours, not the CRS default.
// Per-Ingress extraDirectives (e.g. SecRuleRemoveById, custom SecRule entries)
// are injected after the CRS Includes so they operate on already-defined rules,
// but before SecRuleEngine so they cannot override the enforcement mode.
func wafHandler(mode string, extraDirectives []string) map[string]interface{} {
	ruleEngine := "DetectionOnly"
	if strings.EqualFold(mode, "On") {
		ruleEngine = "On"
	}
	directives := []string{
		"Include @coraza.conf-recommended",
		"Include @crs-setup.conf.example",
		"Include @owasp_crs/*.conf",
	}
	directives = append(directives, extraDirectives...)
	directives = append(directives,
		fmt.Sprintf("SecRuleEngine %s", ruleEngine),
		"SecRequestBodyAccess On",
		"SecResponseBodyAccess Off",
		"SecRequestBodyLimit 13107200",
	)
	return map[string]interface{}{
		"handler":        "waf",
		"load_owasp_crs": true,
		"directives":     directives,
	}
}

// reverseProxyHandler returns the Caddy reverse_proxy handler JSON, applying
// any per-Ingress proxy timeouts, real-IP injection, and custom request headers.
func reverseProxyHandler(upstream string, injectRealIP bool, proxy proxyConfig, plainHTTP bool, reqHdrs headerConfig) map[string]interface{} {
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

	// Build upstream request headers — merge all sources into one set map.
	reqHeaders := map[string][]string{}
	if injectRealIP {
		proto, port := "https", "443"
		if plainHTTP {
			proto, port = "http", "80"
		}
		reqHeaders["X-Real-IP"] = []string{"{client_ip}"}
		reqHeaders["X-Forwarded-For"] = []string{"{client_ip}"}
		reqHeaders["X-Forwarded-Proto"] = []string{proto}
		reqHeaders["X-Forwarded-Host"] = []string{"{http.request.host}"}
		reqHeaders["X-Forwarded-Port"] = []string{port}
	}
	if proxy.upstreamVhost != "" {
		reqHeaders["Host"] = []string{proxy.upstreamVhost}
	}
	if proxy.xForwardedPrefix != "" {
		reqHeaders["X-Forwarded-Prefix"] = []string{proxy.xForwardedPrefix}
	}
	// Merge per-Ingress custom request headers (annotation overrides same-named
	// built-in headers like X-Forwarded-For if explicitly set).
	for k, v := range reqHdrs.set {
		reqHeaders[k] = []string{v}
	}

	reqSection := map[string]interface{}{}
	if len(reqHeaders) > 0 {
		reqSection["set"] = reqHeaders
	}
	if len(reqHdrs.delete) > 0 {
		reqSection["delete"] = reqHdrs.delete
	}
	if len(reqSection) > 0 {
		h["headers"] = map[string]interface{}{
			"request": reqSection,
		}
	}

	if proxy.retries > 0 {
		h["load_balancing"] = map[string]interface{}{
			"retries": proxy.retries,
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
