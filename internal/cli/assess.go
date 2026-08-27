package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/QYVORA/qyvora-shaka/internal/assess"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

func newAssessCmd() *cobra.Command {
	var (
		limit      int
		groupsOnly bool
	)
	cmd := &cobra.Command{
		Use:     "assess",
		Aliases: []string{"scan"},
		Short:   "Run the full assessment pipeline (discover→enumerate→graph→analyze→findings→risk)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAssess(cmd.Context(), cmd, assess.Full(), limit, groupsOnly)
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "cap objects enumerated per kind (0 = unlimited)")
	cmd.Flags().BoolVar(&groupsOnly, "identity", false, "identity-focused: enumerate users and groups only")
	registerDirFlags(cmd.Flags())
	return cmd
}

func newDiscoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "discover",
		Aliases: []string{"find"},
		Short:   "Discover domains and domain controllers",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDiscover(cmd.Context(), cmd)
		},
	}
	registerDirFlags(cmd.Flags())
	return cmd
}

func newEnumerateCmd() *cobra.Command {
	var object string
	var limit int
	cmd := &cobra.Command{
		Use:     "enumerate [users|groups|computers|ous|trusts|all]",
		Aliases: []string{"enum"},
		Short:   "Enumerate directory objects",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			obj := object
			if len(args) == 1 {
				obj = args[0]
			}
			return runEnumerate(cmd.Context(), cmd, obj, limit)
		},
	}
	cmd.Flags().StringVar(&object, "object", "all", "users, groups, computers, ous, trusts, or all")
	cmd.Flags().IntVar(&limit, "limit", 0, "cap objects enumerated (0 = unlimited)")
	registerDirFlags(cmd.Flags())
	return cmd
}

func newAnalyzeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "analyze",
		Aliases: []string{"rules"},
		Short:   "Run the rule engine and risk assessment over the latest session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAnalyze(cmd.Context(), cmd)
		},
	}
}

func newFindingsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "findings",
		Aliases: []string{"finds"},
		Short:   "List findings from the latest session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFindings(cmd.Context())
		},
	}
}

func newEvidenceCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "evidence",
		Aliases: []string{"ev"},
		Short:   "List evidence collected in the latest session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEvidence(cmd.Context())
		},
	}
}

func newGraphCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "graph",
		Aliases: []string{"path"},
		Short:   "Render the relationship graph from the latest session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runGraph(cmd.Context())
		},
	}
}

func newReportCmd() *cobra.Command {
	var format string
	var out string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render an assessment report from the latest session",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(cmd.Context(), format, out)
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "", "terminal, markdown, html, json, yaml")
	cmd.Flags().StringVar(&out, "out", "", "write report to file (default stdout)")
	return cmd
}

// runAssess runs the full pipeline.
func runAssess(ctx context.Context, cmd *cobra.Command, base assess.Options, limit int, groupsOnly bool) error {
	base.Limit = limit
	base.GroupsOnly = groupsOnly
	base.FollowUp = true
	sess, err := app.runAssessment(ctx, cmd, dirFlagsFrom(cmd), base)
	if err != nil {
		return err
	}
	return renderSession(ctx, sess)
}

// runDiscover runs only the discovery stage.
func runDiscover(ctx context.Context, cmd *cobra.Command) error {
	sess, err := app.runAssessment(ctx, cmd, dirFlagsFrom(cmd), assess.Options{Discover: true})
	if err != nil {
		return err
	}
	return renderSession(ctx, sess)
}

// runEnumerate runs discovery + enumeration for the selected object set.
func runEnumerate(ctx context.Context, cmd *cobra.Command, object string, limit int) error {
	opts := assess.Options{Discover: true, Enumerate: true, Limit: limit}
	if object == "users" || object == "groups" {
		opts.GroupsOnly = true
	}
	sess, err := app.runAssessment(ctx, cmd, dirFlagsFrom(cmd), opts)
	if err != nil {
		return err
	}
	return renderObjectSlice(ctx, sess, object)
}

// runAnalyze renders the latest session's findings/risk.
func runAnalyze(ctx context.Context, cmd *cobra.Command) error {
	sess, err := latestSession()
	if err != nil {
		return err
	}
	return renderSession(ctx, sess)
}

func runFindings(ctx context.Context) error {
	sess, err := latestSession()
	if err != nil {
		return err
	}
	return renderFindings(sess)
}

func runEvidence(ctx context.Context) error {
	sess, err := latestSession()
	if err != nil {
		return err
	}
	return renderEvidence(sess)
}

func runGraph(ctx context.Context) error {
	sess, err := latestSession()
	if err != nil {
		return err
	}
	return renderGraph(sess)
}

func runReport(ctx context.Context, format, out string) error {
	sess, err := latestSession()
	if err != nil {
		return err
	}
	if format == "" {
		format = string(app.printer.Format())
	}
	return writeReport(sess, format, out)
}

// latestSession loads the most recently saved session.
func latestSession() (*models.Session, error) {
	ids, err := app.store.List()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errNoSession
	}
	return app.store.Load(ids[len(ids)-1])
}

func newToolsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "tools",
		Aliases: []string{"capabilities", "caps"},
		Short:   "List shaka's AI-ready tool capabilities",
		Run: func(_ *cobra.Command, _ []string) {
			printCapabilitiesTable()
		},
	}
}
