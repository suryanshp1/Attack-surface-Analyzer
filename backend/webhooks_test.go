package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestWebhookDispatchSlack(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NotificationWebhook{
		ID:                "wh-1",
		URL:               "https://hooks.example.invalid/test",
		WebhookType:       "slack",
		Enabled:           true,
		NotifyOnNewAssets: true,
	}

	payload := WebhookPayload{
		Event:     "new_asset",
		Title:     "New asset discovered",
		Detail:    "api.example.com",
		Timestamp: now(),
	}

	err := DispatchWebhook(context.Background(), webhookFixtureClient(srv), wh, payload)
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}

	var data map[string]any
	if err := json.Unmarshal(receivedBody, &data); err != nil {
		t.Fatalf("invalid json received: %v", err)
	}

	if !strings.Contains(data["text"].(string), "New asset discovered") {
		t.Fatalf("unexpected slack text: %v", data["text"])
	}
}

func TestWebhookDispatchDiscord(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NotificationWebhook{
		ID:                "wh-2",
		URL:               "https://hooks.example.invalid/test",
		WebhookType:       "discord",
		Enabled:           true,
		NotifyOnTakeovers: true,
	}

	payload := WebhookPayload{
		Event:     "takeover",
		Title:     "Subdomain takeover candidate detected",
		Detail:    "sub.example.com pointing to unclaimed AWS S3",
		Timestamp: now(),
	}

	err := DispatchWebhook(context.Background(), webhookFixtureClient(srv), wh, payload)
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}

	var data map[string]any
	if err := json.Unmarshal(receivedBody, &data); err != nil {
		t.Fatalf("invalid json received: %v", err)
	}

	if !strings.Contains(data["content"].(string), "Subdomain takeover candidate") {
		t.Fatalf("unexpected discord content: %v", data["content"])
	}
}

func TestWebhookFilterTrigger(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	wh := NotificationWebhook{
		ID:                "wh-3",
		URL:               "https://hooks.example.invalid/test",
		WebhookType:       "generic",
		Enabled:           true,
		NotifyOnNewAssets: false, // disabled for new_assets
	}

	payload := WebhookPayload{
		Event:     "new_asset",
		Title:     "New asset discovered",
		Detail:    "test.example.com",
		Timestamp: now(),
	}

	err := DispatchWebhook(context.Background(), webhookFixtureClient(srv), wh, payload)
	if err != nil {
		t.Fatalf("dispatch error: %v", err)
	}
	if called {
		t.Fatal("webhook was called despite trigger being disabled")
	}
}

// Only test code rewrites validated public URLs to isolated local receivers.
type webhookRoundTripper func(*http.Request) (*http.Response, error)

func (f webhookRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func webhookFixtureClient(srv *httptest.Server) *http.Client {
	client := newWebhookClient()
	client.Transport = webhookRoundTripper(func(r *http.Request) (*http.Response, error) {
		target, _ := url.Parse(srv.URL)
		clone := r.Clone(r.Context())
		dest := *r.URL
		dest.Scheme = target.Scheme
		dest.Host = target.Host
		clone.URL = &dest
		return http.DefaultTransport.RoundTrip(clone)
	})
	return client
}

func TestWebhookURLPolicy(t *testing.T) {
	for _, raw := range []string{"http://hooks.example.com/hook", "https://127.0.0.1/hook", "https://[::1]/", "https://[::ffff:127.0.0.1]/", "https://169.254.169.254/", "https://10.0.0.1/", "https://hooks.example.com:8080/", "https://user:secret@hooks.example.com/", "https://hooks.example.com/#secret", "https:///hook", "https://hooks.example.com/" + strings.Repeat("x", 4096)} {
		if validateWebhookURL(raw) == nil {
			t.Errorf("unsafe URL accepted: %s", raw)
		}
	}
	for _, raw := range []string{"https://hooks.slack.com/services/synthetic", "https://discord.com:443/api/webhooks/synthetic", "https://1.1.1.1/hook"} {
		if err := validateWebhookURL(raw); err != nil {
			t.Errorf("valid URL rejected: %v", err)
		}
	}
	for _, address := range []string{"127.0.0.1:443", "[::1]:443", "169.254.169.254:443", "[::ffff:127.0.0.1]:443", "1.1.1.1:80"} {
		if c, err := dialWebhook(context.Background(), "tcp", address); err == nil {
			c.Close()
			t.Fatalf("unsafe dial accepted: %s", address)
		}
	}
}

func TestWebhookRedirectsBlocked(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		calls := 0
		client := newWebhookClient()
		client.Transport = webhookRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls > 1 {
				t.Fatal("redirect followed")
			}
			return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"http://127.0.0.1/internal"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		})
		err := DispatchWebhook(context.Background(), client, NotificationWebhook{URL: "https://hooks.example.invalid/secret", Enabled: true}, WebhookPayload{Event: "test"})
		if err == nil || calls != 1 {
			t.Fatalf("redirect %d accepted: %v", status, err)
		}
	}
}

func TestWebhookSecretsStayServerSide(t *testing.T) {
	t.Setenv("API_TOKEN", "test-owner")
	s := testServer(t)
	call := func(token, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.handle(w, r)
		return w
	}
	raw := "https://hooks.example.invalid/services/synthetic-path-secret?sig=synthetic-query-secret"
	body, _ := json.Marshal(map[string]string{"url": raw, "webhookType": "generic"})
	created := call("test-owner", "POST", "/api/webhooks", string(body))
	if created.Code != 201 {
		t.Fatal(created.Code, created.Body.String())
	}
	s.state.Audit = append(s.state.Audit, Event{Title: "Webhook created", Detail: raw})
	member := call("test-owner", "POST", "/api/members", `{"name":"Audit viewer","role":"viewer"}`)
	var access struct{ Token string }
	json.Unmarshal(member.Body.Bytes(), &access)
	if member.Code != 201 || access.Token == "" {
		t.Fatal(member.Code)
	}
	for _, token := range []string{"test-owner", access.Token} {
		for _, path := range []string{"/api/state", "/api/webhooks"} {
			response := call(token, "GET", path, "")
			if response.Code != 200 {
				t.Fatal(response.Code)
			}
			if strings.Contains(response.Body.String(), "synthetic-path-secret") || strings.Contains(response.Body.String(), "synthetic-query-secret") {
				t.Fatalf("secret leaked through %s", path)
			}
		}
	}
	if strings.Contains(created.Body.String(), "synthetic-path-secret") {
		t.Fatal("creation response leaked secret")
	}
	if len(s.state.Webhooks) != 1 || s.state.Webhooks[0].URL != raw {
		t.Fatal("stored delivery URL was changed")
	}
	if !strings.Contains(s.state.Audit[len(s.state.Audit)-1].Detail, "synthetic-path-secret") {
		t.Fatal("legacy audit history was modified")
	}
	if call(access.Token, "POST", "/api/webhooks/test", `{"url":"https://hooks.example.invalid"}`).Code != 403 {
		t.Fatal("viewer may dispatch")
	}
	if call("test-owner", "POST", "/api/webhooks/test", `{"id":"missing","url":"https://hooks.example.invalid"}`).Code != 404 {
		t.Fatal("missing ID silently fell back to URL")
	}
	if call("test-owner", "POST", "/api/webhooks/test", `{invalid`).Code != 400 {
		t.Fatal("invalid JSON accepted")
	}
	if call("test-owner", "POST", "/api/webhooks/test", `{"url":"https://127.0.0.1"}`).Code != 400 {
		t.Fatal("private destination accepted")
	}
	var saved NotificationWebhook
	json.Unmarshal(created.Body.Bytes(), &saved)
	deleted := call("test-owner", "DELETE", "/api/webhooks?id="+saved.ID, "")
	if deleted.Code != 200 || len(s.state.Webhooks) != 0 {
		t.Fatal("webhook deletion failed")
	}
}

func TestWebhookTestDoesNotHoldWorkspaceLock(t *testing.T) {
	t.Setenv("API_TOKEN", "test-owner")
	s := testServer(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, context.Canceled
	}}
	defer func() { net.DefaultResolver = previous }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		r := httptest.NewRequest("POST", "/api/webhooks/test", strings.NewReader(`{"url":"https://hooks.example.invalid"}`))
		r.Header.Set("Authorization", "Bearer test-owner")
		s.handle(httptest.NewRecorder(), r)
	}()
	defer func() { close(release); <-done }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("delivery did not start")
	}
	read := make(chan int, 1)
	go func() {
		r := httptest.NewRequest("GET", "/api/me", nil)
		r.Header.Set("Authorization", "Bearer test-owner")
		w := httptest.NewRecorder()
		s.handle(w, r)
		read <- w.Code
	}()
	select {
	case code := <-read:
		if code != 200 {
			t.Fatal(code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook delivery blocked API")
	}
}

func TestWebhookDNSDestinationsCheckedOnEveryDelivery(t *testing.T) {
	for _, addresses := range [][]string{{"127.0.0.1"}, {"1.1.1.1", "127.0.0.1"}, {"1.1.1.1", "::1"}} {
		t.Run(strings.Join(addresses, ","), func(t *testing.T) {
			upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			go func() {
				buf := make([]byte, 4096)
				for {
					n, peer, err := upstream.ReadFrom(buf)
					if err != nil {
						return
					}
					var msg dnsmessage.Message
					if msg.Unpack(buf[:n]) != nil {
						continue
					}
					msg.Header.Response = true
					msg.Header.Authoritative = true
					for _, q := range msg.Questions {
						for _, raw := range addresses {
							ip := netip.MustParseAddr(raw)
							var body dnsmessage.ResourceBody
							if q.Type == dnsmessage.TypeA && ip.Is4() {
								body = &dnsmessage.AResource{A: ip.As4()}
							}
							if q.Type == dnsmessage.TypeAAAA && ip.Is6() {
								body = &dnsmessage.AAAAResource{AAAA: ip.As16()}
							}
							if body != nil {
								msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 1}, Body: body})
							}
						}
					}
					packed, err := msg.Pack()
					if err == nil {
						_, _ = upstream.WriteTo(packed, peer)
					}
				}
			}()
			previous := net.DefaultResolver
			net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", upstream.LocalAddr().String())
			}}
			defer func() { net.DefaultResolver = previous }()
			if err := validateWebhookURL("https://hooks.example.invalid/synthetic-secret"); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				conn, err := dialWebhook(context.Background(), "tcp", "hooks.example.invalid:443")
				if conn != nil {
					conn.Close()
					t.Fatal("unsafe destination dialed")
				}
				if err == nil || !strings.Contains(err.Error(), "must be public") {
					t.Fatalf("private or mixed DNS result not rejected: %v", err)
				}
			}
		})
	}
}

func TestWebhookConnectionErrorsOmitCredentialURL(t *testing.T) {
	client := newWebhookClient()
	client.Transport = webhookRoundTripper(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("synthetic connection error for %s", r.URL)
	})
	err := DispatchWebhook(context.Background(), client, NotificationWebhook{URL: "https://hooks.example.invalid/synthetic-secret?sig=private", Enabled: true}, WebhookPayload{Event: "test"})
	if err == nil || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(err.Error(), "sig=") {
		t.Fatalf("unsafe error: %v", err)
	}
}
