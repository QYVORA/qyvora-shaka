// Package orchestration coordinates the assessment pipeline: stage list,
// profile selection, and progress. The CLI and console both call these same
// services so one-shot and interactive use never diverge.
package orchestration

import (
	"context"
	"fmt"
	"time"

	"github.com/QYVORA/qyvora-shaka/internal/core"
	"github.com/QYVORA/qyvora-shaka/internal/events"
)

// Profile selects which stages run and how deep the assessment goes.
type Profile string

// Profiles mirror the documented set.
const (
	ProfileQuick          Profile = "quick"
	ProfileStandard       Profile = "standard"
	ProfileDeep           Profile = "deep"
	ProfileDirectory      Profile = "directory"
	ProfileAuthentication Profile = "authentication"
	ProfileTrust          Profile = "trust"
	ProfileIdentity       Profile = "identity"
	ProfileCompliance     Profile = "compliance"
	ProfileResearch       Profile = "research"
)

// Profiles lists every supported profile in documentation order.
var Profiles = []Profile{
	ProfileQuick, ProfileStandard, ProfileDeep, ProfileDirectory,
	ProfileAuthentication, ProfileTrust, ProfileIdentity,
	ProfileCompliance, ProfileResearch,
}

// IsValid reports whether name is a known profile.
func IsValid(name string) bool {
	for _, p := range Profiles {
		if string(p) == name {
			return true
		}
	}
	return false
}

// ErrNoStages is returned when a pipeline is executed without stages.
var ErrNoStages = fmt.Errorf("orchestration pipeline has no stages")

// StageFactory creates a pipeline stage. The CLI supplies it with the
// directory service and profile-specific settings so the pipeline stays
// transport-agnostic.
type StageFactory func(env *core.Env) core.Stage

// Pipeline runs stages against a shared Env.
type Pipeline struct {
	stages []core.Stage
}

// NewPipeline returns an empty pipeline.
func NewPipeline() *Pipeline { return &Pipeline{} }

// Add appends a stage.
func (p *Pipeline) Add(s core.Stage) { p.stages = append(p.stages, s) }

// Stages returns the current stage list.
func (p *Pipeline) Stages() []core.Stage { return p.stages }

// Run executes every stage in order, recording stage names and honoring
// context cancellation.
func (p *Pipeline) Run(ctx context.Context, env *core.Env) error {
	if len(p.stages) == 0 {
		return ErrNoStages
	}
	for _, stage := range p.stages {
		if err := ctx.Err(); err != nil {
			return ctx.Err()
		}
		if env.Session != nil {
			env.Session.Stages = append(env.Session.Stages, stage.Name())
		}
		start := time.Now()
		emitStage(env, events.StageStarted, stage.Name(), nil)
		err := stage.Run(ctx, env)
		emitStage(env, events.StageCompleted, stage.Name(), err)
		reportStage(env, stage.Name(), start, err)
		if err != nil {
			if env.Session != nil {
				env.Session.Errors = append(env.Session.Errors, fmt.Sprintf("%s: %v", stage.Name(), err))
			}
			return fmt.Errorf("stage %s: %w", stage.Name(), err)
		}
	}
	if env.Session != nil {
		env.Session.Finish()
	}
	return nil
}

func emitStage(env *core.Env, name, stage string, err error) {
	if env.Events == nil {
		return
	}
	data := map[string]any{"stage": stage}
	if err != nil {
		data["message"] = err.Error()
		env.Events.Fail(name, data)
		return
	}
	env.Events.Info(name, data)
}

func reportStage(env *core.Env, name string, start time.Time, err error) {
	if env.Log == nil {
		return
	}
	elapsed := time.Since(start).Round(time.Millisecond)
	if err != nil {
		env.Log.Errorf("stage %s failed after %s: %v", name, elapsed, err)
	} else {
		env.Log.Debugf("stage %s completed in %s", name, elapsed)
	}
}
