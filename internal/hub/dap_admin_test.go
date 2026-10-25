package hub

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEvictAgentAdminAPI(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{"deleted", http.StatusNoContent, false},
		{"already gone is success", http.StatusNotFound, false},
		{"online refused", http.StatusConflict, true},
		{"unauthorized", http.StatusUnauthorized, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete || r.URL.Path != "/api/agents/a1" {
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer adm" {
					t.Errorf("missing admin bearer")
				}
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			client, err := NewDapClient(DapConfig{URL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws", AdminToken: "adm"})
			if err != nil {
				t.Fatal(err)
			}
			err = client.EvictAgent(context.Background(), "a1")
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("evict: %v", err)
			}
		})
	}
}

func TestEvictAgentWithoutAdminToken(t *testing.T) {
	client, err := NewDapClient(DapConfig{URL: "wss://hub.fa1.dev/ws"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.EvictAgent(context.Background(), "a1"); !errors.Is(err, ErrAdminTokenMissing) {
		t.Fatalf("err = %v, want ErrAdminTokenMissing", err)
	}
}

func TestAdminBase(t *testing.T) {
	for _, tc := range []struct{ ws, want string }{
		{"wss://hub.fa1.dev/ws", "https://hub.fa1.dev"},
		{"ws://127.0.0.1:8080/ws", "http://127.0.0.1:8080"},
	} {
		client, err := NewDapClient(DapConfig{URL: tc.ws})
		if err != nil {
			t.Fatal(err)
		}
		base, err := client.adminBase()
		if err != nil || base != tc.want {
			t.Fatalf("adminBase(%s) = %q, %v; want %q", tc.ws, base, err, tc.want)
		}
	}
}
