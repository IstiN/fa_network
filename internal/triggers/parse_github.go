package triggers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

type ghUser struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

type ghActor struct {
	user ghUser
}

func (a ghActor) actor() actor { return actor{login: a.user.Login, typ: a.user.Type} }

type ghPayload struct {
	Action     string `json:"action"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Comment struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
		User ghUser `json:"user"`
	} `json:"comment"`
	Issue struct {
		Number   int    `json:"number"`
		Title    string `json:"title"`
		Body     string `json:"body"`
		User     ghUser `json:"user"`
		Assignee ghUser `json:"assignee"`
	} `json:"issue"`
	PullRequest struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
		Body   string `json:"body"`
		User   ghUser `json:"user"`
	} `json:"pull_request"`
	Review struct {
		Body string `json:"body"`
		User ghUser `json:"user"`
	} `json:"review"`
	Sender ghUser `json:"sender"`
}

// parseGitHub normalizes issue_comment / pull_request_review_comment /
// pull_request_review / issues / pull_request deliveries (plus ping).
func parseGitHub(header http.Header, body []byte, opts ParseOptions) (*Event, error) {
	event := header.Get("X-GitHub-Event")
	if event == "ping" {
		return &Event{Kind: KindPing}, nil
	}
	var p ghPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("github payload: %w", err)
	}
	switch event {
	case "issue_comment":
		return ghCommentEvent(&p, "issues", p.Issue.Number, opts)
	case "pull_request_review_comment":
		return ghCommentEvent(&p, "pulls", p.PullRequest.Number, opts)
	case "pull_request_review":
		return ghReviewEvent(&p, opts)
	case "issues":
		return ghIssueEvent(&p, opts)
	case "pull_request":
		return ghPREvent(&p, opts)
	}
	return ignored("unsupported_event"), nil
}

func ghTrigger(p *ghPayload, number int) *Trigger {
	t := &Trigger{
		Provider:    "github",
		TargetRepo:  p.Repository.FullName,
		SessionKey:  SessionKey("gh", p.Repository.FullName, strconv.Itoa(number)),
		IssueNumber: strconv.Itoa(number),
	}
	if p.Comment.ID > 0 {
		t.CommentID = strconv.FormatInt(p.Comment.ID, 10)
	}
	return t
}

// ghCommentEvent covers issue_comment and pull_request_review_comment
// (action created); reaction kind selects the reactions API family.
func ghCommentEvent(p *ghPayload, kind string, number int, opts ParseOptions) (*Event, error) {
	if p.Action != "created" {
		return ignored("unsupported_action"), nil
	}
	t := ghTrigger(p, number)
	reaction := &Reaction{Repo: p.Repository.FullName, CommentID: t.CommentID, Kind: kind}
	return triggerEvent(t, ghActor{user: p.Comment.User}.actor(), p.Comment.Body, reaction, opts), nil
}

func ghReviewEvent(p *ghPayload, opts ParseOptions) (*Event, error) {
	if p.Action != "submitted" {
		return ignored("unsupported_action"), nil
	}
	t := ghTrigger(p, p.PullRequest.Number)
	return triggerEvent(t, ghActor{user: p.Review.User}.actor(), p.Review.Body, nil, opts), nil
}

// ghIssueEvent covers issues.opened (mention required) and
// issues.assigned to the configured bot user (implicit mention).
func ghIssueEvent(p *ghPayload, opts ParseOptions) (*Event, error) {
	t := ghTrigger(p, p.Issue.Number)
	switch p.Action {
	case "opened":
		return triggerEvent(t, ghActor{user: p.Issue.User}.actor(), p.Issue.Body, nil, opts), nil
	case "assigned":
		if !IsListedBot(p.Issue.Assignee.Login, opts.BotLogins) {
			return ignored("not_assigned_to_fa"), nil
		}
		a := ghActor{user: p.Sender}
		if a.user.Login == "" {
			a.user = p.Issue.User
		}
		return assignedEvent(t, a.actor(), p.Issue.Body, opts), nil
	}
	return ignored("unsupported_action"), nil
}

func ghPREvent(p *ghPayload, opts ParseOptions) (*Event, error) {
	if p.Action != "opened" {
		return ignored("unsupported_action"), nil
	}
	t := ghTrigger(p, p.PullRequest.Number)
	return triggerEvent(t, ghActor{user: p.PullRequest.User}.actor(), p.PullRequest.Body, nil, opts), nil
}
