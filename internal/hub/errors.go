package hub

import "errors"

// errOffline mirrors the real client's Send failure while disconnected.
var errOffline = errors.New("dap: hub offline")

// ErrUnknownOperation marks a hub that does not implement a requested dap
// operation (notably enroll_create on older hubs).
var ErrUnknownOperation = errors.New("dap: unknown enrollment operation")
