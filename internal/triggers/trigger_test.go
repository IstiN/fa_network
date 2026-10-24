package triggers

import (
	"regexp"
	"strings"
	"testing"
)

func TestHasMention(t *testing.T) {
	cases := []struct {
		text, mention string
		want          bool
	}{
		{"@fa please fix", "@fa", true},
		{"hello @FA there", "@fa", true},
		{"(@fa) do it", "@fa", true},
		{"/fa run", "@fa", true},
		{"@fab no", "@fa", false},
		{"no mention", "@fa", false},
		{"email fa@example.com", "@fa", false},
		{"@helper hi", "@helper", true},
		{"@fa default empty mention", "", true},
	}
	for _, c := range cases {
		if got := HasMention(c.text, c.mention); got != c.want {
			t.Errorf("HasMention(%q, %q) = %v, want %v", c.text, c.mention, got, c.want)
		}
	}
}

func TestIsBot(t *testing.T) {
	opts := ParseOptions{BotLogins: DefaultBotLogins}
	if !IsBot("someone", "Bot", opts) {
		t.Error("userType Bot must be ignored")
	}
	if !IsBot("dependabot[bot]", "User", opts) {
		t.Error("[bot] suffix must be ignored")
	}
	if !IsBot("AI-Teammate", "User", opts) {
		t.Error("configured bot login must match case-insensitively")
	}
	if IsBot("human", "User", opts) {
		t.Error("human must not be treated as bot")
	}
	if IsBot("someone", "Bot", ParseOptions{AllowBots: true}) {
		t.Error("AllowBots explicitly permits bot authors")
	}
	if !IsListedBot("fa", DefaultBotLogins) || IsListedBot("nobody", DefaultBotLogins) {
		t.Error("IsListedBot mismatch")
	}
}

func TestSessionKey(t *testing.T) {
	if got := SessionKey("gh", "Owner/Repo", "42"); got != "gh-owner-repo-42" {
		t.Fatalf("basic key = %q", got)
	}
	if got := SessionKey("gl", "group/sub/proj", "7"); got != "gl-group-sub-proj-7" {
		t.Fatalf("gitlab key = %q", got)
	}
	long := strings.Repeat("verylongowner", 8) + "/" + strings.Repeat("r", 80)
	key := SessionKey("gh", long, "42")
	if len(key) > 63 {
		t.Fatalf("long key not truncated: %d", len(key))
	}
	if !regexp.MustCompile(`^[a-z0-9-]{3,63}$`).MatchString(key) {
		t.Fatalf("key shape: %q", key)
	}
	if !strings.HasSuffix(key, "-42") {
		t.Fatalf("issue number lost: %q", key)
	}
	if other := SessionKey("gh", long+"x", "42"); other == key {
		t.Fatal("hash must distinguish different long repos")
	}
}

func TestNormalizeSessionKey(t *testing.T) {
	if got := NormalizeSessionKey("My Custom Key!"); got != "my-custom-key" {
		t.Fatalf("normalize = %q", got)
	}
	short := NormalizeSessionKey("a")
	if len(short) < 3 || len(short) > 63 {
		t.Fatalf("short key not padded: %q", short)
	}
	if got := NormalizeSessionKey(strings.Repeat("x", 100)); len(got) != 63 {
		t.Fatalf("long custom key len = %d", len(got))
	}
	if got := NormalizeSessionKey(""); len(got) < 3 {
		t.Fatalf("empty key = %q", got)
	}
	if got := TruncateKey("abc-"); got != "abc" {
		t.Fatalf("trailing dash: %q", got)
	}
}

func TestProviderKeyPrefix(t *testing.T) {
	for in, want := range map[string]string{"github": "gh", "gitlab": "gl", "bitbucket": "bb", "jira": "gen"} {
		if got := ProviderKeyPrefix(in); got != want {
			t.Errorf("ProviderKeyPrefix(%q) = %q", in, got)
		}
	}
}
