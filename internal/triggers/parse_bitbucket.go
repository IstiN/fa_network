package triggers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

type bbPayload struct {
	Actor struct {
		Nickname string `json:"nickname"`
		Username string `json:"username"`
		Type     string `json:"type"`
	} `json:"actor"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Comment struct {
		ID      int64 `json:"id"`
		Content struct {
			Raw string `json:"raw"`
		} `json:"content"`
	} `json:"comment"`
	PullRequest struct {
		ID          int64  `json:"id"`
		Title       string `json:"title"`
		Description string `json:"description"`
	} `json:"pullrequest"`
	Issue struct {
		ID int64 `json:"id"`
	} `json:"issue"`
}

// parseBitbucket normalizes pullrequest:comment_created,
// issue:comment_created and pullrequest:created deliveries.
func parseBitbucket(header http.Header, body []byte, opts ParseOptions) (*Event, error) {
	var p bbPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("bitbucket payload: %w", err)
	}
	a := actor{login: p.Actor.Nickname, typ: p.Actor.Type}
	if a.login == "" {
		a.login = p.Actor.Username
	}
	switch header.Get("X-Event-Key") {
	case "pullrequest:comment_created":
		t := bbTrigger(&p, p.PullRequest.ID)
		t.CommentID = strconv.FormatInt(p.Comment.ID, 10)
		return triggerEvent(t, a, p.Comment.Content.Raw, nil, opts), nil
	case "issue:comment_created":
		t := bbTrigger(&p, p.Issue.ID)
		t.CommentID = strconv.FormatInt(p.Comment.ID, 10)
		return triggerEvent(t, a, p.Comment.Content.Raw, nil, opts), nil
	case "pullrequest:created":
		t := bbTrigger(&p, p.PullRequest.ID)
		return triggerEvent(t, a, p.PullRequest.Description, nil, opts), nil
	}
	return ignored("unsupported_event"), nil
}

func bbTrigger(p *bbPayload, id int64) *Trigger {
	n := strconv.FormatInt(id, 10)
	return &Trigger{
		Provider:    "bitbucket",
		TargetRepo:  p.Repository.FullName,
		SessionKey:  SessionKey("bb", p.Repository.FullName, n),
		IssueNumber: n,
	}
}
