// Package assess runs a complete assessment: it builds the environment and
// executes the pipeline stages against a directory service, producing a
// finished session with objects, graph, findings, evidence and risk. Both the
// CLI one-shot commands and the interactive console funnel through this single
// Runner so behavior never diverges.
package assess

import (
	"context"
	"io"

	"github.com/spf13/viper"

	"github.com/QYVORA/qyvora-shaka/internal/core"
	"github.com/QYVORA/qyvora-shaka/internal/directory"
	"github.com/QYVORA/qyvora-shaka/internal/events"
	"github.com/QYVORA/qyvora-shaka/internal/evidence"
	"github.com/QYVORA/qyvora-shaka/internal/graph"
	"github.com/QYVORA/qyvora-shaka/internal/logger"
	"github.com/QYVORA/qyvora-shaka/internal/orchestration"
	"github.com/QYVORA/qyvora-shaka/internal/pipeline"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// Options tunes a single assessment run.
type Options struct {
	Profile      string
	Limit        int
	GroupsOnly   bool
	FollowUp     bool
	MaxDepth     int
	EventsWriter io.Writer
	StoreDir     string

	// Stage toggles. All default to true (full pipeline).
	Discover  bool
	Enumerate bool
	Graph     bool
	Analysis  bool
	Findings  bool
	Risk      bool
}

// Full returns options with every stage enabled.
func Full() Options {
	return Options{Discover: true, Enumerate: true, Graph: true, Analysis: true, Findings: true, Risk: true}
}

// Result is the outcome of an assessment run.
type Result struct {
	Session *models.Session
	Env     *core.Env
}

// Runner owns the state needed to run assessments.
type Runner struct {
	Dir     directory.Service
	Target  *models.Target
	Log     *logger.Logger
	Config  *viper.Viper
	Options Options
}

// New returns a runner bound to the given directory service and target.
func New(dir directory.Service, target *models.Target, log *logger.Logger, cfg *viper.Viper) *Runner {
	if log == nil {
		log = logger.New()
	}
	if cfg == nil {
		cfg = viper.New()
	}
	return &Runner{Dir: dir, Target: target, Log: log, Config: cfg}
}

// Run performs the assessment and returns the finished session and env.
func (r *Runner) Run(ctx context.Context) (*Result, error) {
	ses := models.NewSession()
	if r.Target != nil {
		ses.TargetID = r.Target.ID
		ses.Profile = firstNonEmpty(r.Options.Profile, r.Target.Profile)
	} else {
		ses.Profile = r.Options.Profile
	}

	g := graph.New()
	ev := evidence.New()
	var stream *events.Stream
	if r.Options.EventsWriter != nil {
		stream = events.NewStream(r.Options.EventsWriter)
		ses.ID = stream.ExecutionID()
	}

	env := &core.Env{
		Target: r.Target, Session: ses, Graph: g, Dir: r.Dir, Evidence: ev,
		Log: r.Log, Config: r.Config, Events: stream,
	}

	p := r.buildPipeline(env)
	if err := p.Run(ctx, env); err != nil {
		return &Result{Session: ses, Env: env}, err
	}
	return &Result{Session: ses, Env: env}, nil
}

func (r *Runner) buildPipeline(_ *core.Env) *orchestration.Pipeline {
	p := orchestration.NewPipeline()
	o := r.Options
	all := !o.Discover && !o.Enumerate && !o.Graph && !o.Analysis && !o.Findings && !o.Risk
	if o.Discover || all {
		p.Add(&pipeline.DiscoveryStage{})
	}
	if o.Enumerate || all {
		p.Add(&pipeline.EnumerationStage{Options: pipeline.Options{
			Limit: o.Limit, GroupsOnly: o.GroupsOnly, IncludeTrusts: true,
		}})
	}
	if o.Graph || all {
		p.Add(&pipeline.GraphStage{})
	}
	if o.Analysis || all {
		p.Add(&pipeline.AnalysisStage{FollowUp: o.FollowUp})
	}
	if o.Findings || all {
		p.Add(&pipeline.FindingsStage{})
	}
	if o.Risk || all {
		p.Add(&pipeline.RiskStage{})
	}
	return p
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
