package triggers

import "testing"

// Review #12: provider-specific bot identities must not trigger CI loops.
func TestIsBotProviderIdentities(t *testing.T) {
	opts := ParseOptions{BotLogins: DefaultBotLogins}
	cases := []struct {
		login, typ string
		want       bool
	}{
		{"project_123_bot_abc", "", true}, // GitLab project access-token bot
		{"group_9_bot_def", "", true},     // GitLab group bot
		{"deploy_bot", "", true},          // suffix form
		{"ci-app", "app", true},           // Bitbucket app user
		{"github-actions[bot]", "Bot", true},
		{"human", "user", false},
		{"robot", "", false}, // no substring over-matching
		{"kb-agent", "", false},
		{"fa", "", true}, // configured denylist still applies
	}
	for _, tc := range cases {
		if got := IsBot(tc.login, tc.typ, opts); got != tc.want {
			t.Errorf("IsBot(%q,%q) = %v, want %v", tc.login, tc.typ, got, tc.want)
		}
	}
	// AllowBots opt-out still wins.
	if IsBot("project_1_bot_x", "app", ParseOptions{AllowBots: true}) {
		t.Error("AllowBots must disable the filter")
	}
}
