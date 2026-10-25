// Package triggers implements the universal SCM/CI webhook ingress and
// CI wake-up bridge (issue #3): provider payload normalization, mention
// filtering with bot loop prevention, deterministic session keys, and
// workflow/pipeline/build dispatch toward the universal CI worker.
package triggers

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// Event kinds returned by Parse.
const (
	KindPing    = "ping"
	KindIgnored = "ignored"
	KindTrigger = "trigger"
)

// Trigger is one normalized wake-up request, independent of the SCM that
// produced it. Field names mirror the fa-universal.yml workflow inputs.
type Trigger struct {
	Provider    string
	TargetRepo  string
	SessionKey  string
	IssueNumber string
	CommentID   string
	Author      string
	Prompt      string
	Runner      string
	Metadata    map[string]any
}

// Reaction describes an optional best-effort 👀 acknowledgement on the
// originating GitHub comment. Kind is "issues" or "pulls" (the two
// comment reaction API families).
type Reaction struct {
	Repo      string
	CommentID string
	Kind      string
}

// Event is the outcome of parsing one authenticated webhook delivery.
type Event struct {
	Kind     string
	Reason   string // set when Kind == KindIgnored
	Trigger  *Trigger
	Reaction *Reaction
}

func ignored(reason string) *Event { return &Event{Kind: KindIgnored, Reason: reason} }

// ParseOptions tunes mention matching and bot loop prevention.
type ParseOptions struct {
	Mention   string
	BotLogins []string
	AllowBots bool
}

// DefaultBotLogins is the loop-prevention denylist (FA_TRIGGER_BOT_LOGINS
// overrides it).
var DefaultBotLogins = []string{"fa", "fa-bot", "fa[bot]", "github-actions[bot]", "ai-teammate"}

// HasMention reports whether text carries the trigger mention: the
// configured @mention (default @fa) as a case-insensitive word, or the
// /fa command form.
func HasMention(text, mention string) bool {
	name := strings.TrimPrefix(strings.TrimSpace(mention), "@")
	if name == "" {
		name = "fa"
	}
	quoted := regexp.QuoteMeta(name)
	pattern := `(?i)(^|[\s(])@` + quoted + `\b|/` + quoted + `\b`
	return regexp.MustCompile(pattern).MatchString(text)
}

// IsBot reports whether an actor must be ignored for loop prevention.
func IsBot(login, userType string, opts ParseOptions) bool {
	if opts.AllowBots {
		return false
	}
	if strings.EqualFold(userType, "Bot") || strings.EqualFold(userType, "app") {
		return true // GitHub bots; Bitbucket app users
	}
	lower := strings.ToLower(login)
	if strings.HasSuffix(lower, "[bot]") || strings.HasSuffix(lower, "_bot") || strings.Contains(lower, "_bot_") {
		return true // GitLab project/group access-token bots carry no actor type
	}
	return IsListedBot(login, opts.BotLogins)
}

// IsListedBot reports whether login is one of the configured bot logins
// (used both for loop prevention and for issues.assigned targeting).
func IsListedBot(login string, botLogins []string) bool {
	login = strings.ToLower(login)
	for _, bot := range botLogins {
		if login == strings.ToLower(bot) {
			return true
		}
	}
	return false
}

// SanitizeKey lowercases and folds every non [a-z0-9] run into single
// dashes, trimming leading/trailing dashes (no length limit).
func SanitizeKey(s string) string {
	var b strings.Builder
	lastDash := true
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// TruncateKey caps a sanitized key at 63 chars without a trailing dash.
func TruncateKey(s string) string {
	if len(s) > 63 {
		s = s[:63]
	}
	return strings.TrimRight(s, "-")
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

// NormalizeSessionKey sanitizes a caller-provided session key into the
// [a-z0-9-]{3,63} shape (hash-padded when too short).
func NormalizeSessionKey(custom string) string {
	key := TruncateKey(SanitizeKey(custom))
	if len(key) >= 3 {
		return key
	}
	return TruncateKey(SanitizeKey(key + "-" + shortHash(custom)))
}

// SessionKey builds the deterministic <prefix>-<repo>-<number> key. Keys
// longer than 63 chars degrade to <prefix>-<hash8>-<repoName>-<number> so
// the number and a collision-resistant hash always survive.
func SessionKey(prefix, repo, number string) string {
	raw := prefix + "-" + repo + "-" + number
	if key := SanitizeKey(raw); len(key) <= 63 {
		return key
	}
	repoName := repo
	if i := strings.LastIndex(repo, "/"); i >= 0 {
		repoName = repo[i+1:]
	}
	// Degrade to <prefix>-<hash8>-<repoName>-<number>: the number always
	// survives, the repo name yields first.
	head := prefix + "-" + shortHash(raw)
	suffix := "-" + SanitizeKey(number)
	name := SanitizeKey(repoName)
	if budget := 63 - len(head) - len(suffix) - 1; len(name) > budget && budget > 0 {
		name = strings.TrimRight(name[:budget], "-")
	}
	return TruncateKey(head + "-" + name + suffix)
}

// ProviderKeyPrefix maps a generic-webhook provider to its key prefix.
func ProviderKeyPrefix(provider string) string {
	switch provider {
	case "github":
		return "gh"
	case "gitlab":
		return "gl"
	case "bitbucket":
		return "bb"
	}
	return "gen"
}
