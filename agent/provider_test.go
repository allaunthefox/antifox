package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestConnectionSendsSessionHeader: when a session header is configured, the connection test must also send it (with a non-empty header value); otherwise gateways like opencode return 400 for a missing session id and the test result won't match real runs.
func TestConnectionSendsSessionHeader(t *testing.T) {
	const hk = "X-Session-Id"
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(hk)
		if got == "" {
			http.Error(w, `{"error":{"message":"missing session id"}}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer srv.Close()

	cfg := ConfigFrom("openai", "m", srv.URL, "k", "")
	cfg.SessionHeaderKey = hk
	if _, err := TestConnection(context.Background(), cfg); err != nil {
		t.Fatalf("TestConnection with session header: %v", err)
	}
	if got == "" {
		t.Fatalf("expected %s header to be sent", hk)
	}
}

// TestConnectionNoSessionHeaderWhenUnset: no session header is sent when none is configured.
func TestConnectionNoSessionHeaderWhenUnset(t *testing.T) {
	const hk = "X-Session-Id"
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(hk)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer srv.Close()

	cfg := ConfigFrom("openai", "m", srv.URL, "k", "")
	if _, err := TestConnection(context.Background(), cfg); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if got != "" {
		t.Fatalf("expected no %s header when unset, got %q", hk, got)
	}
}
