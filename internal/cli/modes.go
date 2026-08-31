package cli

import (
	"errors"
)

// errNoSession is returned when a command requires a saved session but none
// exists yet.
var errNoSession = errors.New("no session saved; run 'shaka assess' first")
