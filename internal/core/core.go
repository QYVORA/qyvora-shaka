// Package core defines the interfaces and shared environment that connect the
// assessment stages into a pipeline.
package core

import (
	"context"

	"github.com/spf13/viper"

	"github.com/QYVORA/qyvora-shaka/internal/directory"
	"github.com/QYVORA/qyvora-shaka/internal/events"
	"github.com/QYVORA/qyvora-shaka/internal/evidence"
	"github.com/QYVORA/qyvora-shaka/internal/graph"
	"github.com/QYVORA/qyvora-shaka/internal/logger"
	"github.com/QYVORA/qyvora-shaka/pkg/models"
)

// Env is the shared context every pipeline stage receives. It bundles the
// target, session, graph, and the services stages may need.
type Env struct {
	Target   *models.Target
	Session  *models.Session
	Graph    *graph.Graph
	Dir      directory.Service
	Evidence *evidence.Store
	Log      *logger.Logger
	Config   *viper.Viper
	Events   *events.Stream
}

// Stage is one step of the assessment pipeline.
type Stage interface {
	Name() string
	Run(ctx context.Context, env *Env) error
}
