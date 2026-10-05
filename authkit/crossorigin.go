// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"cmp"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// The reasons a refused write is logged with.
const (
	refusedFetchSite = "fetch-site"
	refusedOrigin    = "origin"
	refusedHost      = "host"
	refusedScheme    = "scheme"
)

// CrossOriginConfig parameterizes the cross-origin guard.
type CrossOriginConfig struct {
	// TrustedProxies are the CIDR ranges, as ratelimit.ParseTrustedProxies returns them, whose forwarded headers count.
	TrustedProxies []string
	// PublicURL, when set, is the scheme and host visitors reach the site at, and every write must be sent there.
	PublicURL *url.URL
	// Logger receives a line for every refused write. Nil applies slog.Default.
	Logger *slog.Logger
}

// originGuard judges browser writes against the address they were sent to.
type originGuard struct {
	proxies []netip.Prefix
	public  *url.URL
	logger  *slog.Logger
}

// CrossOriginGuard returns root middleware refusing browser writes from another origin, panicking on a bad proxy range.
func CrossOriginGuard(cfg CrossOriginConfig) func(http.Handler) http.Handler {
	guard := &originGuard{proxies: proxyPrefixes(cfg.TrustedProxies), public: cfg.PublicURL, logger: cfg.Logger}
	if guard.logger == nil {
		guard.logger = slog.Default()
	}
	protection := http.NewCrossOriginProtection()
	protection.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guard.refuse(w, r, refusedFetchSite)
	}))
	return func(next http.Handler) http.Handler {
		protected := protection.Handler(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reason, settled := guard.judge(r)
			switch {
			case reason != "":
				guard.refuse(w, r, reason)
			case settled:
				next.ServeHTTP(w, r)
			default:
				protected.ServeHTTP(w, r)
			}
		})
	}
}

// proxyPrefixes parses the trusted proxy ranges, panicking on one that is not CIDR notation.
func proxyPrefixes(ranges []string) []netip.Prefix {
	parsed := make([]netip.Prefix, 0, len(ranges))
	for _, held := range ranges {
		parsed = append(parsed, netip.MustParsePrefix(held))
	}
	return parsed
}

// judge returns why the guard refuses a write, or whether it settles one the standard library would misjudge.
func (g *originGuard) judge(r *http.Request) (string, bool) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "", false
	}
	if g.public != nil {
		return g.againstPublic(r)
	}
	if r.Header.Get("Sec-Fetch-Site") == "" && r.Header.Get("Origin") != "" {
		return g.againstTarget(r), true
	}
	return "", false
}

// againstPublic returns why a write misses the public address, or whether its Origin alone settles it.
func (g *originGuard) againstPublic(r *http.Request) (string, bool) {
	_, host := g.target(r)
	if !sameOrigin(&url.URL{Scheme: g.public.Scheme, Host: host}, g.public) {
		return refusedHost, true
	}
	if r.Header.Get("Origin") == "" {
		return "", false
	}
	origin, ok := originOf(r)
	if !ok || !sameOrigin(origin, g.public) {
		return refusedOrigin, true
	}
	return "", r.Header.Get("Sec-Fetch-Site") == ""
}

// againstTarget returns why an Origin-only write misses the address it was sent to, or nothing when it matches.
func (g *originGuard) againstTarget(r *http.Request) string {
	origin, ok := originOf(r)
	if !ok {
		return refusedOrigin
	}
	scheme, host := g.target(r)
	if scheme == "" {
		return refusedScheme
	}
	if !sameOrigin(origin, &url.URL{Scheme: scheme, Host: host}) {
		return refusedOrigin
	}
	return ""
}

// originOf returns the request's Origin when it has the scheme and authority form a browser sends.
func originOf(r *http.Request) (*url.URL, bool) {
	parsed, err := url.Parse(r.Header.Get("Origin"))
	if err != nil {
		return nil, false
	}
	return parsed, parsed.Scheme != "" && parsed.Host != "" && parsed.User == nil && parsed.Path == "" &&
		parsed.RawQuery == "" && parsed.Fragment == ""
}

// sameOrigin reports whether two addresses agree on scheme, host name and effective port.
func sameOrigin(one, other *url.URL) bool {
	return strings.EqualFold(one.Scheme, other.Scheme) && strings.EqualFold(one.Hostname(), other.Hostname()) &&
		effectivePort(one) == effectivePort(other)
}

// effectivePort returns the explicit port of u or the default one for its scheme.
func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

// target returns the scheme and host the browser sent the request to, with an empty scheme when a proxy named none.
func (g *originGuard) target(r *http.Request) (string, string) {
	if g.fromProxy(r.RemoteAddr) {
		return proxiedScheme(r), cmp.Or(firstForwarded(r.Header.Get("X-Forwarded-Host")), r.Host)
	}
	if r.TLS != nil {
		return "https", r.Host
	}
	return "http", r.Host
}

// proxiedScheme returns the scheme a trusted proxy names, https over TLS, or nothing when neither says.
func proxiedScheme(r *http.Request) string {
	if forwarded := firstForwarded(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		return forwarded
	}
	if r.TLS != nil {
		return "https"
	}
	return ""
}

// fromProxy reports whether the peer address sits inside a trusted proxy range.
func (g *originGuard) fromProxy(remoteAddr string) bool {
	addr, ok := peerAddr(remoteAddr)
	return ok && slices.ContainsFunc(g.proxies, func(prefix netip.Prefix) bool { return prefix.Contains(addr) })
}

// peerAddr returns the address a peer connected from, written with or without its port.
func peerAddr(remoteAddr string) (netip.Addr, bool) {
	if peer, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return peer.Addr().Unmap(), true
	}
	addr, err := netip.ParseAddr(remoteAddr)
	return addr.Unmap(), err == nil
}

// firstForwarded returns the first entry of a comma separated forwarded header.
func firstForwarded(header string) string {
	first, _, _ := strings.Cut(header, ",")
	return strings.TrimSpace(first)
}

// refuse answers the write as cross-origin and logs why.
func (g *originGuard) refuse(w http.ResponseWriter, r *http.Request, reason string) {
	_, host := g.target(r)
	g.logger.WarnContext(r.Context(), "write refused", "reason", reason, "method", r.Method, "path", r.URL.Path,
		"host", host, "origin", r.Header.Get("Origin"), "fetch_site", r.Header.Get("Sec-Fetch-Site"))
	w.Header().Set("Cache-Control", "no-store")
	RespondError(w, http.StatusForbidden, ErrorResponse{
		Message: "cross-origin request refused", Code: "request_cross_origin",
	})
}
