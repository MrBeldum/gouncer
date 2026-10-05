// SPDX-License-Identifier: Apache-2.0

package authkit_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gopherium/gouncer/authkit"
)

// siteHost is the address the guarded site answers on in these tests.
const siteHost = "app.example.com"

// proxyRange is the peer range the proxied cases trust.
const proxyRange = "10.0.0.0/8"

// publicSite is the public address the pinned cases name.
var publicSite = &url.URL{Scheme: "https", Host: siteHost}

// browserCall describes one request as it reaches the guard.
type browserCall struct {
	method         string
	host           string
	remote         string
	fetchSite      string
	origin         string
	forwardedHost  string
	forwardedProto string
	tls            bool
}

// request builds the HTTP request call describes.
func (c browserCall) request() *http.Request {
	method := c.method
	if method == "" {
		method = http.MethodPost
	}
	request := httptest.NewRequest(method, "/api/graphql", nil)
	request.Host = siteHost
	if c.host != "" {
		request.Host = c.host
	}
	if c.remote != "" {
		request.RemoteAddr = c.remote
	}
	headers := map[string]string{
		"Sec-Fetch-Site": c.fetchSite, "Origin": c.origin,
		"X-Forwarded-Host": c.forwardedHost, "X-Forwarded-Proto": c.forwardedProto,
	}
	for name, value := range headers {
		if value != "" {
			request.Header.Set(name, value)
		}
	}
	if c.tls {
		request.TLS = &tls.ConnectionState{}
	}
	return request
}

// guarded wraps a write counter in the guard built from cfg, logging into the returned buffer.
func guarded(cfg authkit.CrossOriginConfig) (http.Handler, *int, *bytes.Buffer) {
	var logged bytes.Buffer
	cfg.Logger = slog.New(slog.NewJSONHandler(&logged, nil))
	writes := 0
	return authkit.CrossOriginGuard(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writes++
		w.WriteHeader(http.StatusNoContent)
	})), &writes, &logged
}

// loggedLine decodes the single JSON line the guard logged.
func loggedLine(t *testing.T, logged *bytes.Buffer) map[string]any {
	t.Helper()
	var line map[string]any
	if err := json.Unmarshal(logged.Bytes(), &line); err != nil {
		t.Fatalf("decoding the log line %q: %v, want one JSON line", logged.String(), err)
	}
	return line
}

// assertRefused fails unless the guard answered the cross-origin refusal, let no write through and logged reason.
func assertRefused(t *testing.T, recorder *httptest.ResponseRecorder, writes int, logged *bytes.Buffer, reason string) {
	t.Helper()
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if writes != 0 {
		t.Errorf("writes = %d, want none to reach the handler", writes)
	}
	if body := decodeError(t, recorder); body.Code != "request_cross_origin" {
		t.Errorf("code = %q, want request_cross_origin", body.Code)
	}
	if got := loggedLine(t, logged)["reason"]; got != reason {
		t.Errorf("logged reason = %v, want %q", got, reason)
	}
}

// assertLetThrough fails unless the guard handed the write to the handler once and logged nothing.
func assertLetThrough(t *testing.T, recorder *httptest.ResponseRecorder, writes int, logged *bytes.Buffer) {
	t.Helper()
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if writes != 1 {
		t.Errorf("writes = %d, want the request to reach the handler once", writes)
	}
	if logged.Len() != 0 {
		t.Errorf("log = %q, want nothing logged for a request let through", logged.String())
	}
}

func TestCrossOriginGuardRefusesBrowserWritesFromAnotherOrigin(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		call   browserCall
		reason string
	}{
		{name: "cross site", reason: "fetch-site",
			call: browserCall{fetchSite: "cross-site", origin: "https://example.org"}},
		{name: "sibling subdomain", reason: "fetch-site",
			call: browserCall{fetchSite: "same-site", origin: "https://other.example.com"}},
		{name: "cross site put", reason: "fetch-site",
			call: browserCall{method: http.MethodPut, fetchSite: "cross-site", origin: "https://example.org"}},
		{name: "origin only from another host", reason: "origin",
			call: browserCall{origin: "https://example.org", tls: true}},
		{name: "origin only from another port", reason: "origin",
			call: browserCall{origin: "https://app.example.com:8443", tls: true}},
		{name: "origin only from plain http to https", reason: "origin",
			call: browserCall{origin: "http://app.example.com", tls: true}},
		{name: "origin only from https to plain http", reason: "origin",
			call: browserCall{origin: "https://app.example.com"}},
		{name: "origin only from another host and scheme", reason: "origin",
			call: browserCall{origin: "http://example.org", tls: true}},
		{name: "origin only from plain http on the same explicit port", reason: "origin",
			call: browserCall{host: "app.example.com:8443", origin: "http://app.example.com:8443", tls: true}},
		{name: "opaque origin", reason: "origin",
			call: browserCall{origin: "null"}},
		{name: "origin carrying a path", reason: "origin",
			call: browserCall{origin: "https://app.example.com/form", tls: true}},
		{name: "origin carrying user info", reason: "origin",
			call: browserCall{origin: "https://someone@app.example.com", tls: true}},
		{name: "origin carrying a query", reason: "origin",
			call: browserCall{origin: "https://app.example.com?page=1", tls: true}},
		{name: "origin carrying a fragment", reason: "origin",
			call: browserCall{origin: "https://app.example.com#top", tls: true}},
		{name: "origin that does not parse", reason: "origin",
			call: browserCall{origin: "://app.example.com", tls: true}},
		{name: "forwarded host from an untrusted peer", reason: "origin",
			call: browserCall{
				host: "app:8080", remote: "203.0.113.5:1234", origin: "https://app.example.com",
				forwardedHost: siteHost, forwardedProto: "https",
			}},
		{name: "forwarded scheme from an untrusted peer", reason: "origin",
			call: browserCall{remote: "203.0.113.5:1234", origin: "https://app.example.com", forwardedProto: "https"}},
		{name: "trusted proxy naming no scheme", reason: "scheme",
			call: browserCall{
				host: "app:8080", remote: "10.0.0.2:1234", origin: "https://app.example.com", forwardedHost: siteHost,
			}},
		{name: "trusted proxy naming no scheme for a page on another site", reason: "scheme",
			call: browserCall{
				host: "app:8080", remote: "10.0.0.2:1234", origin: "https://example.org", forwardedHost: siteHost,
			}},
		{name: "trusted proxy naming another port", reason: "origin",
			call: browserCall{
				host: "app:8080", remote: "10.0.0.2:1234", origin: "https://app.example.com",
				forwardedHost: "app.example.com:444", forwardedProto: "https",
			}},
		{name: "trusted proxy naming a scheme no page uses", reason: "origin",
			call: browserCall{
				host: "app:8080", remote: "10.0.0.2:1234", origin: "https://app.example.com",
				forwardedHost: siteHost, forwardedProto: "wss",
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, writes, logged := guarded(authkit.CrossOriginConfig{TrustedProxies: []string{proxyRange}})
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, tc.call.request())

			assertRefused(t, recorder, *writes, logged, tc.reason)
		})
	}
}

func TestCrossOriginGuardLetsTheSiteAndOtherServersWrite(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		call browserCall
	}{
		{name: "same origin browser write", call: browserCall{fetchSite: "same-origin", origin: "https://app.example.com"}},
		{name: "address typed by the user", call: browserCall{fetchSite: "none"}},
		{name: "origin only over https", call: browserCall{origin: "https://app.example.com", tls: true}},
		{name: "origin only over plain http", call: browserCall{origin: "http://app.example.com"}},
		{name: "origin naming the default port", call: browserCall{origin: "https://app.example.com:443", tls: true}},
		{name: "origin in another letter case", call: browserCall{origin: "https://APP.example.com", tls: true}},
		{name: "origin on an IPv6 host", call: browserCall{host: "[::1]:8080", origin: "http://[::1]:8080"}},
		{name: "server write without browser headers", call: browserCall{}},
		{name: "cross site read", call: browserCall{
			method: http.MethodGet, fetchSite: "cross-site", origin: "https://example.org",
		}},
		{name: "origin only head", call: browserCall{method: http.MethodHead, origin: "https://example.org"}},
		{name: "origin only options", call: browserCall{method: http.MethodOptions, origin: "https://example.org"}},
		{name: "trusted proxy naming the site", call: browserCall{
			host: "app:8080", remote: "10.0.0.2:1234", origin: "https://app.example.com",
			forwardedHost: siteHost, forwardedProto: "https",
		}},
		{name: "trusted proxy naming the default port", call: browserCall{
			host: "app:8080", remote: "10.0.0.2:1234", origin: "https://app.example.com",
			forwardedHost: "app.example.com:443", forwardedProto: "HTTPS",
		}},
		{name: "trusted proxy naming the scheme in capitals and no port", call: browserCall{
			host: "app:8080", remote: "10.0.0.2:1234", origin: "https://app.example.com",
			forwardedHost: siteHost, forwardedProto: "HTTPS",
		}},
		{name: "trusted proxy chain", call: browserCall{
			host: "app:8080", remote: "10.0.0.2:1234", origin: "https://app.example.com",
			forwardedHost: "app.example.com, app:8080", forwardedProto: "https, http",
		}},
		{name: "trusted proxy over tls naming no scheme", call: browserCall{
			remote: "10.0.0.2:1234", origin: "https://app.example.com", tls: true,
		}},
		{name: "trusted proxy as a mapped address", call: browserCall{
			host: "app:8080", remote: "[::ffff:10.0.0.2]:1234", origin: "https://app.example.com",
			forwardedHost: siteHost, forwardedProto: "https",
		}},
		{name: "trusted proxy as a bare address", call: browserCall{
			host: "app:8080", remote: "10.0.0.2", origin: "https://app.example.com",
			forwardedHost: siteHost, forwardedProto: "https",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, writes, logged := guarded(authkit.CrossOriginConfig{TrustedProxies: []string{proxyRange}})
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, tc.call.request())

			assertLetThrough(t, recorder, *writes, logged)
		})
	}
}

func TestCrossOriginGuardIgnoresAnUnreadablePeerAddress(t *testing.T) {
	t.Parallel()

	handler, writes, _ := guarded(authkit.CrossOriginConfig{TrustedProxies: []string{proxyRange}})
	call := browserCall{
		host: "app:8080", remote: "@", origin: "https://app.example.com",
		forwardedHost: siteHost, forwardedProto: "https",
	}
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, call.request())

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if *writes != 0 {
		t.Errorf("writes = %d, want the forwarded headers ignored", *writes)
	}
}

func TestCrossOriginGuardAnswersAnUncachedJSONError(t *testing.T) {
	t.Parallel()

	handler, _, _ := guarded(authkit.CrossOriginConfig{})
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, browserCall{fetchSite: "cross-site", origin: "https://example.org"}.request())

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if got := recorder.Body.String(); got != `{"error":"cross-origin request refused","code":"request_cross_origin"}` {
		t.Errorf("body = %s, want the message and the code", got)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestCrossOriginGuardLogsTheRefusedWrite(t *testing.T) {
	t.Parallel()

	handler, _, logged := guarded(authkit.CrossOriginConfig{TrustedProxies: []string{proxyRange}})
	call := browserCall{
		host: "app:8080", remote: "10.0.0.2:1234", fetchSite: "same-site", origin: "https://other.example.com",
		forwardedHost: siteHost, forwardedProto: "https",
	}

	handler.ServeHTTP(httptest.NewRecorder(), call.request())

	line := loggedLine(t, logged)
	want := map[string]any{
		"level": "WARN", "msg": "write refused", "reason": "fetch-site", "method": http.MethodPost,
		"path": "/api/graphql", "host": siteHost, "origin": "https://other.example.com", "fetch_site": "same-site",
	}
	for key, value := range want {
		if line[key] != value {
			t.Errorf("log %s = %v, want %v", key, line[key], value)
		}
	}
}

func TestCrossOriginGuardLogsToTheDefaultLoggerWhenGivenNone(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	var logged bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logged, nil)))
	handler := authkit.CrossOriginGuard(authkit.CrossOriginConfig{})(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	handler.ServeHTTP(httptest.NewRecorder(), browserCall{origin: "https://example.org"}.request())

	if reason := loggedLine(t, &logged)["reason"]; reason != "origin" {
		t.Errorf("logged reason = %v, want origin on the default logger", reason)
	}
}

func TestCrossOriginGuardPanicsOnAMalformedProxyRange(t *testing.T) {
	t.Parallel()

	for _, entry := range []string{"10.0.0.2", "nonsense", "10.0.0.0/33"} {
		t.Run(entry, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Errorf("CrossOriginGuard() returned, want a panic over the proxy range %q", entry)
				}
			}()

			authkit.CrossOriginGuard(authkit.CrossOriginConfig{TrustedProxies: []string{entry}})
		})
	}
}

func TestCrossOriginGuardKeepsItsOwnCopyOfTheTrustedProxies(t *testing.T) {
	t.Parallel()

	proxies := []string{"192.0.2.0/24"}
	handler, writes, _ := guarded(authkit.CrossOriginConfig{TrustedProxies: proxies})
	proxies[0] = proxyRange
	call := browserCall{
		host: "app:8080", remote: "10.0.0.2:1234", origin: "https://app.example.com",
		forwardedHost: siteHost, forwardedProto: "https",
	}
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, call.request())

	if recorder.Code != http.StatusForbidden || *writes != 0 {
		t.Errorf("status = %d, writes = %d, want a later change to the caller's slice ignored", recorder.Code, *writes)
	}
}

func TestCrossOriginGuardPinnedToAPublicAddressRefusesWritesSentElsewhere(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		call   browserCall
		reason string
	}{
		{name: "another domain pointed at the server", reason: "host",
			call: browserCall{host: "other.example.org", fetchSite: "same-origin", origin: "https://other.example.org"}},
		{name: "the server's own address", reason: "host", call: browserCall{host: "10.0.0.5:8080"}},
		{name: "the public host on another port", reason: "host", call: browserCall{host: "app.example.com:8443"}},
		{name: "a forwarded host from an untrusted peer", reason: "host",
			call: browserCall{
				host: "app:8080", remote: "203.0.113.5:1234", fetchSite: "same-origin",
				origin: "https://app.example.com", forwardedHost: siteHost,
			}},
		{name: "a page on another site", reason: "origin", call: browserCall{origin: "https://example.org"}},
		{name: "a page on the public host over plain http", reason: "origin",
			call: browserCall{origin: "http://app.example.com"}},
		{name: "a page on the public host on another port", reason: "origin",
			call: browserCall{origin: "https://app.example.com:8443"}},
		{name: "an opaque origin", reason: "origin", call: browserCall{origin: "null"}},
		{name: "a browser naming another site", reason: "fetch-site", call: browserCall{fetchSite: "cross-site"}},
		{name: "the public origin from a page the browser calls another site", reason: "fetch-site",
			call: browserCall{fetchSite: "cross-site", origin: "https://app.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, writes, logged := guarded(authkit.CrossOriginConfig{
				TrustedProxies: []string{proxyRange}, PublicURL: publicSite,
			})
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, tc.call.request())

			assertRefused(t, recorder, *writes, logged, tc.reason)
		})
	}
}

func TestCrossOriginGuardPinnedToAPublicAddressKeepsTheSitesOwnWrites(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		call browserCall
	}{
		{name: "a browser on the public page",
			call: browserCall{fetchSite: "same-origin", origin: "https://app.example.com"}},
		{name: "an older browser on the public page", call: browserCall{origin: "https://app.example.com"}},
		{name: "a server naming no page", call: browserCall{}},
		{name: "the public host with its default port",
			call: browserCall{host: "app.example.com:443", origin: "https://app.example.com"}},
		{name: "the public host in capitals", call: browserCall{host: "APP.Example.com", origin: "HTTPS://APP.EXAMPLE.COM"}},
		{name: "an older browser behind a proxy naming no scheme", call: browserCall{
			host: "app:8080", remote: "10.0.0.2:1234", origin: "https://app.example.com", forwardedHost: siteHost,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, writes, logged := guarded(authkit.CrossOriginConfig{
				TrustedProxies: []string{proxyRange}, PublicURL: publicSite,
			})
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, tc.call.request())

			assertLetThrough(t, recorder, *writes, logged)
		})
	}
}

func TestCrossOriginGuardPinnedToAPublicAddressComparesItsPort(t *testing.T) {
	t.Parallel()

	public := &url.URL{Scheme: "http", Host: "localhost:8081"}
	for host, want := range map[string]int{
		"localhost:8081": http.StatusNoContent,
		"localhost":      http.StatusForbidden,
		"[::1]:8081":     http.StatusForbidden,
	} {
		handler, _, _ := guarded(authkit.CrossOriginConfig{PublicURL: public})
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, browserCall{host: host}.request())

		if recorder.Code != want {
			t.Errorf("a write sent to %s = %d, want %d", host, recorder.Code, want)
		}
	}
}

func TestCrossOriginGuardPinnedToAPublicAddressLeavesReadsOpen(t *testing.T) {
	t.Parallel()

	handler, writes, logged := guarded(authkit.CrossOriginConfig{PublicURL: publicSite})
	call := browserCall{
		method: http.MethodGet, host: "other.example.org", fetchSite: "same-origin", origin: "https://other.example.org",
	}
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, call.request())

	assertLetThrough(t, recorder, *writes, logged)
}
