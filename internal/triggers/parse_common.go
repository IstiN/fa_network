package triggers

// actor is the normalized event author for loop prevention.
type actor struct {
	login string
	typ   string
}

// triggerEvent applies bot loop prevention and mention filtering, then
// finalizes the trigger. All SCM comment/opened paths funnel through it.
func triggerEvent(t *Trigger, a actor, text string, reaction *Reaction, opts ParseOptions) *Event {
	if IsBot(a.login, a.typ, opts) {
		return ignored("bot_author")
	}
	if !HasMention(text, opts.Mention) {
		return ignored("no_mention")
	}
	return finalize(t, a, text, reaction)
}

// assignedEvent handles issues.assigned: the mention is implicit (the
// issue was assigned to the configured bot user), loop prevention stays.
func assignedEvent(t *Trigger, a actor, text string, opts ParseOptions) *Event {
	if IsBot(a.login, a.typ, opts) {
		return ignored("bot_author")
	}
	return finalize(t, a, text, nil)
}

func finalize(t *Trigger, a actor, text string, reaction *Reaction) *Event {
	t.Prompt = text
	t.Author = a.login
	return &Event{Kind: KindTrigger, Trigger: t, Reaction: reaction}
}
