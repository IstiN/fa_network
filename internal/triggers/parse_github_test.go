package triggers

import (
	"net/http"
	"testing"
)

func ghEvent(t *testing.T, event string, payload string) *Event {
	t.Helper()
	h := http.Header{"X-Github-Event": []string{event}}
	ev, err := parseGitHub(h, []byte(payload), ParseOptions{Mention: "@fa", BotLogins: DefaultBotLogins})
	if err != nil {
		t.Fatalf("parse %s: %v", event, err)
	}
	return ev
}

const ghCommentPayload = `{
  "action":"created",
  "repository":{"full_name":"Owner/Repo"},
  "issue":{"number":42},
  "comment":{"id":123456,"body":"@fa please fix the tests","user":{"login":"human","type":"User"}}
}`

func TestGitHubPing(t *testing.T) {
	if ev := ghEvent(t, "ping", `{}`); ev.Kind != KindPing {
		t.Fatalf("ping = %+v", ev)
	}
}

func TestGitHubIssueComment(t *testing.T) {
	ev := ghEvent(t, "issue_comment", ghCommentPayload)
	if ev.Kind != KindTrigger {
		t.Fatalf("expected trigger, got %+v", ev)
	}
	tr := ev.Trigger
	if tr.SessionKey != "gh-owner-repo-42" || tr.IssueNumber != "42" || tr.CommentID != "123456" {
		t.Fatalf("trigger = %+v", tr)
	}
	if tr.Provider != "github" || tr.TargetRepo != "Owner/Repo" || tr.Author != "human" {
		t.Fatalf("trigger identity = %+v", tr)
	}
	if tr.Prompt != "@fa please fix the tests" {
		t.Fatalf("prompt = %q", tr.Prompt)
	}
	if ev.Reaction == nil || ev.Reaction.Kind != "issues" || ev.Reaction.CommentID != "123456" || ev.Reaction.Repo != "Owner/Repo" {
		t.Fatalf("reaction = %+v", ev.Reaction)
	}
}

func TestGitHubNoMentionAndBots(t *testing.T) {
	ev := ghEvent(t, "issue_comment", `{"action":"created","repository":{"full_name":"o/r"},"issue":{"number":1},"comment":{"id":5,"body":"just a comment","user":{"login":"human"}}}`)
	if ev.Kind != KindIgnored || ev.Reason != "no_mention" {
		t.Fatalf("no mention = %+v", ev)
	}
	ev = ghEvent(t, "issue_comment", `{"action":"created","repository":{"full_name":"o/r"},"issue":{"number":1},"comment":{"id":5,"body":"@fa go","user":{"login":"github-actions[bot]","type":"Bot"}}}`)
	if ev.Kind != KindIgnored || ev.Reason != "bot_author" {
		t.Fatalf("bot = %+v", ev)
	}
	ev = ghEvent(t, "issue_comment", `{"action":"edited","comment":{"body":"@fa go"}}`)
	if ev.Kind != KindIgnored || ev.Reason != "unsupported_action" {
		t.Fatalf("edited = %+v", ev)
	}
}

func TestGitHubReviewCommentAndReview(t *testing.T) {
	ev := ghEvent(t, "pull_request_review_comment", `{"action":"created","repository":{"full_name":"o/r"},"pull_request":{"number":7},"comment":{"id":99,"body":"@fa look","user":{"login":"human"}}}`)
	if ev.Kind != KindTrigger || ev.Trigger.SessionKey != "gh-o-r-7" || ev.Reaction.Kind != "pulls" {
		t.Fatalf("review comment = %+v", ev)
	}
	ev = ghEvent(t, "pull_request_review", `{"action":"submitted","repository":{"full_name":"o/r"},"pull_request":{"number":7},"review":{"body":"@fa ship it","user":{"login":"human"}}}`)
	if ev.Kind != KindTrigger || ev.Trigger.CommentID != "" || ev.Reaction != nil {
		t.Fatalf("review = %+v", ev)
	}
	ev = ghEvent(t, "pull_request_review", `{"action":"edited"}`)
	if ev.Kind != KindIgnored {
		t.Fatalf("review wrong action = %+v", ev)
	}
}

func TestGitHubIssuesAndPR(t *testing.T) {
	ev := ghEvent(t, "issues", `{"action":"opened","repository":{"full_name":"o/r"},"issue":{"number":3,"body":"@fa new bug","user":{"login":"human"}}}`)
	if ev.Kind != KindTrigger || ev.Trigger.SessionKey != "gh-o-r-3" || ev.Trigger.CommentID != "" {
		t.Fatalf("issues.opened = %+v", ev)
	}
	ev = ghEvent(t, "issues", `{"action":"assigned","repository":{"full_name":"o/r"},"issue":{"number":3,"body":"fix me","assignee":{"login":"fa"},"user":{"login":"human"}},"sender":{"login":"human"}}`)
	if ev.Kind != KindTrigger || ev.Trigger.Prompt != "fix me" {
		t.Fatalf("issues.assigned = %+v", ev)
	}
	ev = ghEvent(t, "issues", `{"action":"assigned","repository":{"full_name":"o/r"},"issue":{"number":3,"assignee":{"login":"someone-else"}},"sender":{"login":"human"}}`)
	if ev.Kind != KindIgnored || ev.Reason != "not_assigned_to_fa" {
		t.Fatalf("assigned other = %+v", ev)
	}
	ev = ghEvent(t, "issues", `{"action":"assigned","repository":{"full_name":"o/r"},"issue":{"number":3,"assignee":{"login":"fa"}},"sender":{"login":"fa-bot"}}`)
	if ev.Kind != KindIgnored || ev.Reason != "bot_author" {
		t.Fatalf("assigned by bot = %+v", ev)
	}
	ev = ghEvent(t, "issues", `{"action":"closed"}`)
	if ev.Kind != KindIgnored || ev.Reason != "unsupported_action" {
		t.Fatalf("issues.closed = %+v", ev)
	}
	ev = ghEvent(t, "pull_request", `{"action":"opened","repository":{"full_name":"o/r"},"pull_request":{"number":11,"body":"@fa review","user":{"login":"human"}}}`)
	if ev.Kind != KindTrigger || ev.Trigger.SessionKey != "gh-o-r-11" {
		t.Fatalf("pr.opened = %+v", ev)
	}
	ev = ghEvent(t, "pull_request", `{"action":"synchronize"}`)
	if ev.Kind != KindIgnored {
		t.Fatalf("pr sync = %+v", ev)
	}
}

func TestGitHubUnsupportedAndMalformed(t *testing.T) {
	if ev := ghEvent(t, "star", `{}`); ev.Kind != KindIgnored || ev.Reason != "unsupported_event" {
		t.Fatalf("star = %+v", ev)
	}
	h := http.Header{"X-Github-Event": []string{"issue_comment"}}
	if _, err := parseGitHub(h, []byte(`{`), ParseOptions{}); err == nil {
		t.Fatal("malformed JSON must error")
	}
}
