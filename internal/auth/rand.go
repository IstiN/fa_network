package auth

import "crypto/rand"

// randRead is crypto/rand.Read, pulled into a var for tests.
var randRead = rand.Read
