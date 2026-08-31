package cli

import (
	"github.com/spf13/cobra"
)

func newCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "Generate shell completion script",
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(app.printer.Writer())
			case "zsh":
				return cmd.Root().GenZshCompletion(app.printer.Writer())
			case "fish":
				return cmd.Root().GenFishCompletion(app.printer.Writer(), true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletion(app.printer.Writer())
			}
			return nil
		},
	}
	return cmd
}
