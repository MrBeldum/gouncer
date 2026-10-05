// SPDX-License-Identifier: Apache-2.0

package authkit_test

import (
	"bytes"
	"cmp"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gopherium/gouncer/authkit"
)

// siteHost is the address the guarded site answers on in these tests.
const siteHost = "app.example.com"

// proxyPeer is the address a reverse proxy connects from in these tests.
const proxyPeer = "10.0.0.2:1234"

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
	request := httptest.NewRequest(cmp.Or(c.method, http.MethodPost), "/api/graphql", nil)
	request.Host = cmp.Or(c.host, siteHost)
	request.RemoteAddr = cmp.Or(c.remote, request.RemoteAddr)
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

// guarded wraps a write counter in the guard, logging into the returned buffer.
func guarded() (http.Handler, *int, *bytes.Buffer) {
	var logged bytes.Buffer
	writes := 0
	return authkit.CrossOriginGuard(slog.New(slog.NewJSONHandler(&logged, nil)))(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
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
		{name: "cross site naming the site as its origin", reason: "fetch-site",
			call: browserCall{fetchSite: "cross-site", origin: "https://app.example.com"}},
		{name: "cross site with no origin", reason: "fetch-site", call: browserCall{fetchSite: "cross-site"}},
		{name: "origin only from another host", reason: "origin",
			call: browserCall{origin: "https://example.org", tls: true}},
		{name: "origin only from another port", reason: "origin",
			call: browserCall{origin: "https://app.example.com:8443", tls: true}},
		{name: "opaque origin", reason: "origin", call: browserCall{origin: "null"}},
		{name: "origin only through a proxy forwarding the site's host", reason: "origin",
			call: browserCall{
				host: "app:8080", remote: proxyPeer, origin: "https://app.example.com",
				forwardedHost: siteHost, forwardedProto: "https",
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, writes, logged := guarded()
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, tc.call.request())

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
			}
			if *writes != 0 {
				t.Errorf("writes = %d, want none to reach the handler", *writes)
			}
			if got := loggedLine(t, logged)["reason"]; got != tc.reason {
				t.Errorf("logged reason = %v, want %q", got, tc.reason)
			}
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
		{name: "origin only from an https page over plain http", call: browserCall{origin: "https://app.example.com"}},
		{name: "origin only from a plain http page over https",
			call: browserCall{origin: "http://app.example.com", tls: true}},
		{name: "origin only on an explicit port",
			call: browserCall{host: "app.example.com:8443", origin: "https://app.example.com:8443", tls: true}},
		{name: "origin only on an IPv6 host", call: browserCall{host: "[::1]:8080", origin: "http://[::1]:8080"}},
		{name: "origin only through a proxy forwarding another host", call: browserCall{
			remote: proxyPeer, origin: "https://app.example.com", forwardedHost: "example.org", forwardedProto: "http",
		}},
		{name: "server write without browser headers", call: browserCall{}},
		{name: "server write through a proxy", call: browserCall{
			host: "app:8080", remote: proxyPeer, forwardedHost: siteHost, forwardedProto: "https",
		}},
		{name: "cross site read", call: browserCall{
			method: http.MethodGet, fetchSite: "cross-site", origin: "https://example.org",
		}},
		{name: "origin only head", call: browserCall{method: http.MethodHead, origin: "https://example.org"}},
		{name: "origin only options", call: browserCall{method: http.MethodOptions, origin: "https://example.org"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, writes, logged := guarded()
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, tc.call.request())

			if recorder.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
			}
			if *writes != 1 {
				t.Errorf("writes = %d, want the request to reach the handler once", *writes)
			}
			if logged.Len() != 0 {
				t.Errorf("log = %q, want nothing logged for a request let through", logged.String())
			}
		})
	}
}

func TestCrossOriginGuardAnswersAnUncachedJSONError(t *testing.T) {
	t.Parallel()

	for name, call := range map[string]browserCall{
		"fetch-site": {fetchSite: "cross-site", origin: "https://example.org"},
		"origin":     {origin: "https://example.org"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler, _, _ := guarded()
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, call.request())

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
		})
	}
}

func TestCrossOriginGuardLogsTheRefusedWrite(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		call browserCall
		want map[string]any
	}{
		{
			name: "fetch-site",
			call: browserCall{
				host: "app:8080", remote: proxyPeer, fetchSite: "same-site", origin: "https://other.example.com",
				forwardedHost: siteHost, forwardedProto: "https",
			},
			want: map[string]any{
				"reason": "fetch-site", "host": "app:8080", "origin": "https://other.example.com", "fetch_site": "same-site",
			},
		},
		{
			name: "origin",
			call: browserCall{method: http.MethodDelete, origin: "https://example.org"},
			want: map[string]any{
				"reason": "origin", "method": http.MethodDelete, "host": siteHost, "origin": "https://example.org",
				"fetch_site": "",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, _, logged := guarded()

			handler.ServeHTTP(httptest.NewRecorder(), tc.call.request())

			line := loggedLine(t, logged)
			want := map[string]any{"level": "WARN", "msg": "write refused", "method": http.MethodPost, "path": "/api/graphql"}
			maps.Copy(want, tc.want)
			for key, value := range want {
				if line[key] != value {
					t.Errorf("log %s = %v, want %v", key, line[key], value)
				}
			}
			delete(line, "time")
			if len(line) != len(want) {
				t.Errorf("log = %v, want only the fields %v", line, want)
			}
		})
	}
}

func TestCrossOriginGuardLogsToTheDefaultLoggerWhenGivenNone(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	var logged bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logged, nil)))
	handler := authkit.CrossOriginGuard(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), browserCall{origin: "https://example.org"}.request())

	if reason := loggedLine(t, &logged)["reason"]; reason != "origin" {
		t.Errorf("logged reason = %v, want origin on the default logger", reason)
	}
}
