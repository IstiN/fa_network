package hub

import "errors"

// errOffline mirrors the real client's Send failure while disconnected.
var errOffline = errors.New("dap: hub offline")
