package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/IstiN/fa_network/internal/hub"
	"github.com/IstiN/fa_network/internal/model"
)

// TestRealHubFanet1InteropNewChannel is the end-to-end known-answer
// interop for the «unable to decrypt in newly created private channel»
// incident: a channel created via REST (post-#11 EnsureChannel path),
// fanet1 frames crossing app→DAP and DAP→app through the REAL hub and
// relay. It proves, with real crypto:
//  1. the relay preserves envelope.id as the dap frame id (AAD salt+AD),
//  2. payloads stay byte-identical in both directions (REST, WS, history),
//  3. both directions decrypt with the shared channel keypair.
func TestRealHubFanet1InteropNewChannel(t *testing.T) {
	hubURL := startRealDapHub(t)
	env, _ := newRealHubEnv(t, hubURL)
	ctx := t.Context()

	ownerToken := env.authedToken("owner1", "Owner One")
	networkID := env.createNetwork(t, ownerToken, "interop-net", "secret123")
	ownerSess, _ := env.join(t, networkID, "secret123", "", ownerToken)
	rec := env.do("POST", "/api/networks/"+networkID+"/channels", map[string]string{"name": "fresh-private"}, ownerSess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create channel: %d %s", rec.Code, rec.Body.String())
	}
	var channel map[string]any
	decodeBody(t, rec, &channel)
	channelID, _ := channel["id"].(string)

	rec = env.do("POST", "/api/networks/"+networkID+"/agents/enroll", map[string]string{"name": "interop-agent"}, ownerSess)
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
	}
	var enrolled map[string]any
	decodeBody(t, rec, &enrolled)
	secret, _ := enrolled["clientSecret"].(string)
	agent, err := hub.NewDapClient(hub.DapConfig{URL: hubURL, MasterSecret: secret, Name: "interop-agent"})
	if err != nil {
		t.Fatal(err)
	}
	go agent.Run(ctx)
	waitForCondition(t, "agent online", func() bool { return agent.Online() })
	joinCtx, joinCancel := context.WithTimeout(ctx, 5*time.Second)
	defer joinCancel()
	if err := agent.Join(joinCtx, channelID); err != nil {
		t.Fatalf("agent join: %v", err)
	}

	browser := dialWS(t, env, ownerSess)
	browser.next("roster.snapshot")
	browser.send(map[string]any{"type": "subscribe", "channelId": channelID})
	waitSubscribed(t, browser, channelID)

	channelPriv, channelPub := fanet1RandomKeys(t)

	// ---- 1) app -> DAP agent (REST send, hub delivery) ----
	appPriv, appPub := fanet1RandomKeys(t)
	appFrameID := "interop-app-0001"
	appPlain := `{"t":"msg","body":"app to dap interop"}`
	appPayload, err := fanet1Seal(appPlain, appFrameID, channelID, appPriv, appPub, channelPub, fanet1RandomNonce(t))
	if err != nil {
		t.Fatal(err)
	}
	rec = env.do("POST", "/api/channels/"+channelID+"/messages",
		map[string]string{"id": appFrameID, "payload": appPayload}, ownerSess)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("app send: %d %s", rec.Code, rec.Body.String())
	}
	msg := nextHubMessage(t, agent, appFrameID)
	if msg.Payload != appPayload {
		t.Fatalf("app->DAP payload mutated\n got %s\nwant %s", msg.Payload, appPayload)
	}
	pt, err := fanet1Open(msg.Payload, msg.ID, channelID, channelPriv)
	if err != nil || pt != appPlain {
		t.Fatalf("app->DAP decrypt failed: pt=%q err=%v", pt, err)
	}

	// ---- 2) DAP agent -> app (hub send, WS fanout + history) ----
	agentPriv, agentPub := fanet1RandomKeys(t)
	agentFrameID := "interop-agent-0001"
	agentPlain := `{"t":"msg","body":"dap to app interop"}`
	agentPayload, err := fanet1Seal(agentPlain, agentFrameID, channelID, agentPriv, agentPub, channelPub, fanet1RandomNonce(t))
	if err != nil {
		t.Fatal(err)
	}
	sendCtx, sendCancel := context.WithTimeout(ctx, 5*time.Second)
	defer sendCancel()
	if err := agent.Send(sendCtx, hub.Envelope{ChannelID: channelID, ID: agentFrameID, Payload: agentPayload, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("agent send: %v", err)
	}
	// Skip the sender-echo of the earlier app message; wait for the
	// agent's envelope specifically.
	var wire model.EnvelopeWire
	for {
		frame := browser.next("envelope")
		raw, _ := json.Marshal(frame.Payload)
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Fatal(err)
		}
		if wire.ID == agentFrameID {
			break
		}
	}
	if wire.Payload != agentPayload {
		t.Fatalf("DAP->app WS payload mutated\n got %s\nwant %s", wire.Payload, agentPayload)
	}
	pt, err = fanet1Open(wire.Payload, wire.ID, channelID, channelPriv)
	if err != nil || pt != agentPlain {
		t.Fatalf("DAP->app decrypt failed: pt=%q err=%v", pt, err)
	}

	// History must hold the same ids and byte-identical payloads.
	rec = env.do("GET", "/api/channels/"+channelID+"/messages", nil, ownerSess)
	var page struct {
		Items []model.EnvelopeWire `json:"items"`
	}
	decodeBody(t, rec, &page)
	seen := map[string]string{}
	for _, item := range page.Items {
		seen[item.ID] = item.Payload
	}
	if seen[appFrameID] != appPayload || seen[agentFrameID] != agentPayload {
		t.Fatalf("history payload mismatch: %+v", seen)
	}
}

// nextHubMessage waits for a specific inbound hub envelope id.
func nextHubMessage(t *testing.T, client *hub.DapClient, wantID string) *hub.Envelope {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case ev := <-client.Events():
			if ev.Kind == hub.EventMsg && ev.Msg != nil && ev.Msg.ID == wantID {
				return ev.Msg
			}
		case <-timer.C:
			t.Fatalf("no hub message %s within 10s", wantID)
			return nil
		}
	}
}
