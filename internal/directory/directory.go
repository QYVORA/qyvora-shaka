// Package directory implements the assessment-facing directory service.
//
// It provides a clean abstraction around LDAP communication: connection,
// authentication, queries, filters, paging, attribute decoding, object
// normalization, error handling and timeouts. CLI commands never construct
// low-level LDAP operations directly; they go through this service layer.
package directory

import (
	"context"
	"fmt"
	"time"

	"github.com/QYVORA/qyvora-shaka/internal/ldap"
	"github.com/QYVORA/qyvora-shaka/internal/transport"
)

// Kind identifies the backing directory implementation.
type Kind string

const (
	KindLDAP Kind = "ldap"
	KindSim  Kind = "simulator"
)

// Service is the high-level directory interface used by discovery and
// enumeration engines.
type Service interface {
	// Ping verifies connectivity.
	Ping(ctx context.Context) error
	// RootBaseDN returns the automatic base DN derived from the root DSE.
	RootBaseDN() (string, error)
	// Search runs a subtree search at baseDN.
	Search(ctx context.Context, baseDN, filter string, attrs []string) ([]*transport.Entry, error)
	// Describe returns a human label for the endpoint.
	Describe() string
	// Kind returns the backing implementation.
	Kind() Kind
	// Close releases the connection.
	Close()
}

// Options configures a directory service.
type Options struct {
	// Endpoint is host[:port] for live LDAP.
	Endpoint string
	// BaseDN is the requested base; empty derives from root DSE.
	BaseDN   string
	Username string
	Password string
	UseTLS   bool
	Insecure bool
	Timeout  time.Duration
	PageSize int
	// Sim is a pre-built simulator; when set, Kind() is simulator.
	Sim *Simulator
}

// New builds a Service from options.
func New(ctx context.Context, opts Options) (Service, error) {
	if opts.Sim != nil {
		return &simService{sim: opts.Sim}, nil
	}
	if opts.Endpoint == "" {
		return nil, fmt.Errorf("directory: no endpoint configured")
	}
	addr := opts.Endpoint
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	c, err := ldap.Dial(ctx, ldap.Options{
		Address: addr, BaseDN: opts.BaseDN,
		UseTLS: opts.UseTLS, Insecure: opts.Insecure, Timeout: opts.Timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("directory: dial %s: %w", addr, err)
	}
	if opts.Username != "" {
		if err := c.Bind(ctx, opts.Username, opts.Password); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("directory: bind: %w", err)
		}
	}
	return &ldapService{
		client: c, baseDN: opts.BaseDN, timeout: opts.Timeout,
		pageSize: opts.PageSize, endpoint: addr,
	}, nil
}

type ldapService struct {
	client   *ldap.Client
	baseDN   string
	timeout  time.Duration
	pageSize int
	endpoint string
}

func (s *ldapService) Kind() Kind { return KindLDAP }

func (s *ldapService) Describe() string { return "LDAP " + s.endpoint }

func (s *ldapService) Ping(ctx context.Context) error {
	if _, err := s.RootBaseDN(); err != nil {
		return err
	}
	return nil
}

func (s *ldapService) RootBaseDN() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	dse, err := s.client.RootDSE(ctx)
	if err != nil {
		return "", err
	}
	if s.baseDN != "" {
		return s.baseDN, nil
	}
	if v := dse.Value("defaultNamingContext"); v != "" {
		return v, nil
	}
	if v := dse.Value("rootDomainNamingContext"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("directory: cannot determine base DN")
}

func (s *ldapService) Search(ctx context.Context, baseDN, filter string, attrs []string) ([]*transport.Entry, error) {
	return s.client.Search(ctx, baseDN, filter, attrs, s.pageSize)
}

func (s *ldapService) Close() { _ = s.client.Close() }
