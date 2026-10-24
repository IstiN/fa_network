package triggers

import (
	"net/http"
	"testing"
)

func glEvent(t *testing.T, event, payload string) *Event {
	t.Helper()
	h := http.Header{"X-Gitlab-Event": []string{event}}
	ev, err := parseGitLab(h, []byte(payload), ParseOptions{Mention: "@fa", BotLogins: DefaultBotLogins})
	if err != nil {
		t.Fatalf("parse %s: %v", event, err)
	}
	return ev
}

func TestGitLabNotes(t *testing.T) {
	ev := glEvent(t, "Note Hook", `{"object_kind":"note","user":{"username":"human"},"project":{"path_with_namespace":"group/proj"},"object_attributes":{"id":555,"note":"@fa fix","noteable_type":"MergeRequest"},"merge_request":{"id":9}}`)
	if ev.Kind != KindTrigger || ev.Trigger.SessionKey != "gl-group-proj-9" {
		t.Fatalf("mr note = %+v", ev)
	}
	if ev.Trigger.CommentID != "555" || ev.Trigger.Provider != "gitlab" || ev.Trigger.IssueNumber != "9" {
		t.Fatalf("mr note fields = %+v", ev.Trigger)
	}
	ev = glEvent(t, "Note Hook", `{"user":{"username":"human"},"project":{"path_with_namespace":"g/p"},"object_attributes":{"id":5,"note":"@fa fix","noteable_type":"Issue"},"issue":{"id":4}}`)
	if ev.Kind != KindTrigger || ev.Trigger.SessionKey != "gl-g-p-4" {
		t.Fatalf("issue note = %+v", ev)
	}
	ev = glEvent(t, "Note Hook", `{"object_attributes":{"noteable_type":"Commit","note":"@fa"}}`)
	if ev.Kind != KindIgnored || ev.Reason != "unsupported_noteable" {
		t.Fatalf("commit note = %+v", ev)
	}
	ev = glEvent(t, "Note Hook", `{"user":{"username":"human"},"project":{"path_with_namespace":"g/p"},"object_attributes":{"id":5,"note":"plain","noteable_type":"Issue"},"issue":{"id":4}}`)
	if ev.Kind != KindIgnored || ev.Reason != "no_mention" {
		t.Fatalf("no mention = %+v", ev)
	}
}

func TestGitLabOpenHooks(t *testing.T) {
	ev := glEvent(t, "Issue Hook", `{"user":{"username":"human"},"project":{"path_with_namespace":"g/p"},"object_attributes":{"action":"open","id":12,"description":"@fa new"}}`)
	if ev.Kind != KindTrigger || ev.Trigger.SessionKey != "gl-g-p-12" || ev.Trigger.Prompt != "@fa new" {
		t.Fatalf("issue open = %+v", ev)
	}
	ev = glEvent(t, "Issue Hook", `{"object_attributes":{"action":"update"}}`)
	if ev.Kind != KindIgnored || ev.Reason != "unsupported_action" {
		t.Fatalf("issue update = %+v", ev)
	}
	ev = glEvent(t, "Merge Request Hook", `{"user":{"username":"human"},"project":{"path_with_namespace":"g/p"},"object_attributes":{"action":"open","id":13,"description":"@fa mr"}}`)
	if ev.Kind != KindTrigger || ev.Trigger.IssueNumber != "13" {
		t.Fatalf("mr open = %+v", ev)
	}
	ev = glEvent(t, "Merge Request Hook", `{"object_attributes":{"action":"merge"}}`)
	if ev.Kind != KindIgnored {
		t.Fatalf("mr merge = %+v", ev)
	}
	if ev := glEvent(t, "Pipeline Hook", `{}`); ev.Kind != KindIgnored || ev.Reason != "unsupported_event" {
		t.Fatalf("pipeline = %+v", ev)
	}
	if _, err := parseGitLab(http.Header{}, []byte(`{`), ParseOptions{}); err == nil {
		t.Fatal("malformed gitlab payload must error")
	}
}

func bbEvent(t *testing.T, event, payload string) *Event {
	t.Helper()
	h := http.Header{"X-Event-Key": []string{event}}
	ev, err := parseBitbucket(h, []byte(payload), ParseOptions{Mention: "@fa", BotLogins: DefaultBotLogins})
	if err != nil {
		t.Fatalf("parse %s: %v", event, err)
	}
	return ev
}

func TestBitbucketEvents(t *testing.T) {
	ev := bbEvent(t, "pullrequest:comment_created", `{"actor":{"nickname":"human"},"repository":{"full_name":"ws/repo"},"pullrequest":{"id":21},"comment":{"id":77,"content":{"raw":"@fa go"}}}`)
	if ev.Kind != KindTrigger || ev.Trigger.SessionKey != "bb-ws-repo-21" || ev.Trigger.CommentID != "77" {
		t.Fatalf("pr comment = %+v", ev)
	}
	ev = bbEvent(t, "issue:comment_created", `{"actor":{"username":"human"},"repository":{"full_name":"ws/repo"},"issue":{"id":8},"comment":{"id":78,"content":{"raw":"@fa go"}}}`)
	if ev.Kind != KindTrigger || ev.Trigger.SessionKey != "bb-ws-repo-8" || ev.Trigger.Author != "human" {
		t.Fatalf("issue comment = %+v", ev)
	}
	ev = bbEvent(t, "pullrequest:created", `{"actor":{"nickname":"human"},"repository":{"full_name":"ws/repo"},"pullrequest":{"id":22,"description":"@fa new pr"}}`)
	if ev.Kind != KindTrigger || ev.Trigger.Prompt != "@fa new pr" || ev.Trigger.CommentID != "" {
		t.Fatalf("pr created = %+v", ev)
	}
	ev = bbEvent(t, "pullrequest:created", `{"actor":{"nickname":"fa[bot]"},"repository":{"full_name":"ws/repo"},"pullrequest":{"id":22,"description":"@fa loop"}}`)
	if ev.Kind != KindIgnored || ev.Reason != "bot_author" {
		t.Fatalf("bot = %+v", ev)
	}
	if ev := bbEvent(t, "repo:push", `{}`); ev.Kind != KindIgnored || ev.Reason != "unsupported_event" {
		t.Fatalf("push = %+v", ev)
	}
	if _, err := parseBitbucket(http.Header{}, []byte(`{`), ParseOptions{}); err == nil {
		t.Fatal("malformed bitbucket payload must error")
	}
}

func TestParseGeneric(t *testing.T) {
	ev, err := parseGeneric([]byte(`{"provider":"github","targetRepo":"o/r","issueNumber":"42","commentId":"9","author":"human","prompt":"@fa hi","runner":"github","metadata":{"a":1}}`))
	if err != nil || ev.Kind != KindTrigger {
		t.Fatalf("generic = %+v, %v", ev, err)
	}
	tr := ev.Trigger
	if tr.SessionKey != "gh-o-r-42" || tr.Runner != "github" || tr.Metadata["a"] != float64(1) {
		t.Fatalf("generic trigger = %+v", tr)
	}
	ev, err = parseGeneric([]byte(`{"sessionKey":"My Session","prompt":"go"}`))
	if err != nil || ev.Trigger.SessionKey != "my-session" || ev.Trigger.Provider != "custom" {
		t.Fatalf("custom key = %+v, %v", ev, err)
	}
	if _, err := parseGeneric([]byte(`{"prompt":"no coordinates"}`)); err == nil {
		t.Fatal("missing coordinates must error")
	}
	if _, err := parseGeneric([]byte(`{`)); err == nil {
		t.Fatal("malformed generic payload must error")
	}
	svc := NewService(Config{}, nil)
	if _, err := svc.Parse("nope", http.Header{}, []byte(`{}`)); err == nil {
		t.Fatal("unknown provider must error")
	}
	if _, err := svc.Parse("generic", http.Header{}, []byte(`{"sessionKey":"abc"}`)); err != nil {
		t.Fatalf("service generic parse: %v", err)
	}
}
