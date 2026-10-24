package triggers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

type glPayload struct {
	ObjectKind string `json:"object_kind"`
	User       struct {
		Username string `json:"username"`
	} `json:"user"`
	Project struct {
		PathWithNamespace string `json:"path_with_namespace"`
	} `json:"project"`
	ObjectAttributes struct {
		ID           int64  `json:"id"`
		IID          int64  `json:"iid"`
		Note         string `json:"note"`
		NoteableType string `json:"noteable_type"`
		Action       string `json:"action"`
		Description  string `json:"description"`
	} `json:"object_attributes"`
	Issue struct {
		IID int64 `json:"id"`
	} `json:"issue"`
	MergeRequest struct {
		IID int64 `json:"id"`
	} `json:"merge_request"`
}

// parseGitLab normalizes Note Hook (MR/Issue comments) and
// Issue Hook / Merge Request Hook open events.
func parseGitLab(header http.Header, body []byte, opts ParseOptions) (*Event, error) {
	var p glPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("gitlab payload: %w", err)
	}
	a := actor{login: p.User.Username}
	switch header.Get("X-Gitlab-Event") {
	case "Note Hook":
		return glNoteEvent(&p, a, opts), nil
	case "Issue Hook":
		if p.ObjectAttributes.Action != "open" {
			return ignored("unsupported_action"), nil
		}
		t := glTrigger(&p, firstIID(p.ObjectAttributes.IID, p.ObjectAttributes.ID))
		return triggerEvent(t, a, p.ObjectAttributes.Description, nil, opts), nil
	case "Merge Request Hook":
		if p.ObjectAttributes.Action != "open" {
			return ignored("unsupported_action"), nil
		}
		t := glTrigger(&p, firstIID(p.ObjectAttributes.IID, p.ObjectAttributes.ID))
		return triggerEvent(t, a, p.ObjectAttributes.Description, nil, opts), nil
	}
	return ignored("unsupported_event"), nil
}

// glNoteEvent handles MR / Issue comments only (commit & snippet notes
// are ignored).
func glNoteEvent(p *glPayload, a actor, opts ParseOptions) *Event {
	var number int64
	switch p.ObjectAttributes.NoteableType {
	case "MergeRequest":
		number = firstIID(p.MergeRequest.IID, p.ObjectAttributes.IID)
	case "Issue":
		number = firstIID(p.Issue.IID, p.ObjectAttributes.IID)
	default:
		return ignored("unsupported_noteable")
	}
	t := glTrigger(p, number)
	t.CommentID = strconv.FormatInt(p.ObjectAttributes.ID, 10)
	return triggerEvent(t, a, p.ObjectAttributes.Note, nil, opts)
}

func glTrigger(p *glPayload, number int64) *Trigger {
	n := strconv.FormatInt(number, 10)
	return &Trigger{
		Provider:    "gitlab",
		TargetRepo:  p.Project.PathWithNamespace,
		SessionKey:  SessionKey("gl", p.Project.PathWithNamespace, n),
		IssueNumber: n,
	}
}

// firstIID prefers the human-visible IID over the internal id.
func firstIID(values ...int64) int64 {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}
