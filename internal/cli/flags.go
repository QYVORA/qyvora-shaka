package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// registerDirFlags adds the shared directory connection flags to a flag set.
// They are shared so the same flags work on assess/discover/enumerate.
func registerDirFlags(fs *pflag.FlagSet) {
	fs.String("endpoint", "", "directory endpoint host[:port], e.g. dc01:389")
	fs.String("base-dn", "", "base distinguished name (derived from root DSE if empty)")
	fs.String("user", "", "bind username (empty = anonymous)")
	fs.String("password", "", "bind password")
	fs.Bool("tls", false, "use LDAPS (TLS)")
	fs.Bool("insecure", false, "skip TLS certificate verification")
	fs.Bool("sim", false, "run against the built-in offline demo directory")
}

// dirFlagsFrom reads the directory connection flags from a command.
func dirFlagsFrom(cmd *cobra.Command) dirOptions {
	return dirOptions{
		endpoint: flagString(cmd, "endpoint"),
		baseDN:   flagString(cmd, "base-dn"),
		username: flagString(cmd, "user"),
		password: flagString(cmd, "password"),
		useTLS:   flagBool(cmd, "tls"),
		insecure: flagBool(cmd, "insecure"),
		sim:      flagBool(cmd, "sim"),
	}
}

func flagString(cmd *cobra.Command, name string) string {
	if cmd == nil || cmd.Flags() == nil {
		return ""
	}
	v, _ := cmd.Flags().GetString(name)
	return v
}

func flagBool(cmd *cobra.Command, name string) bool {
	if cmd == nil || cmd.Flags() == nil {
		return false
	}
	v, _ := cmd.Flags().GetBool(name)
	return v
}

func flagInt(cmd *cobra.Command, name string) int {
	if cmd == nil || cmd.Flags() == nil {
		return 0
	}
	v, _ := cmd.Flags().GetInt(name)
	return v
}
