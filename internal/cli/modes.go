package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-shaka/internal/assess"
)

// errNoSession is returned when a command requires a saved session but none
// exists yet.
var errNoSession = errors.New("no session saved; run 'shaka assess' first")

// aggProfile resolves a profile from flags/config/app.
func aggProfile(cmd *cobra.Command) string {
	if v := flagString(cmd, "profile"); v != "" {
		return v
	}
	if app.cfg != nil && app.cfg.IsSet("profile") {
		if v, ok := app.cfg.Get("profile").(string); ok && v != "" {
			return v
		}
	}
	return "standard"
}

// discoverOnly returns options that run only the discovery stage.
func discoverOnly() assess.Options {
	return assess.Options{Discover: true}
}

// enumerationMode maps an object selector to a pipeline configuration.
func enumerationMode(object string) assess.Options {
	o := assess.Options{Discover: true, Enumerate: true}
	switch object {
	case "users", "groups":
		o.GroupsOnly = true
	case "computers", "ous", "trusts", "all":
		// full enumeration
	default:
		o.Enumerate = true
	}
	return o
}
