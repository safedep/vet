// Package enrichers builds the enrichers of a scan: Insights v2 and
// Malysis, and the codeusage and actionrefs enrichers when they are on.
// With no credentials, Insights and Malysis call the community service.
// With an API key, they call the API service of the tenant. actionrefs
// calls the GitHub API.
package enrichers

import (
	"context"
	"errors"
	"time"

	insightsv2grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/insights/v2/insightsv2grpc"
	malysisv1grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	"google.golang.org/grpc"

	"github.com/safedep/vet/v2/internal/credentials"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/actionrefs"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/codeusage"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/insights"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/internal/client"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/malysis"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Options configure the enrichers.
type Options struct {
	// APIURL and CommunityURL are cloud.endpoints.api and
	// cloud.endpoints.community.
	APIURL       string
	CommunityURL string
	Credentials  *credentials.Result
	// Workers bounds the calls of one batch.
	Workers int
	// TTL is the cache time to live.
	TTL time.Duration
	// CodeUsageDir turns on the codeusage enricher for the source files of
	// this directory.
	CodeUsageDir string
	// CodeUsage are the options of the codeusage enricher.
	CodeUsage codeusage.Options
	// ActionRefs turns on the actionrefs enricher.
	ActionRefs *actionrefs.Enricher
}

// Spec is one enricher with its cache identity.
type Spec struct {
	Name    string
	Version string
	TTL     time.Duration
	Plugin  plugin.Enricher
	// Local is an enricher that calls no service. Probe skips it.
	Local bool
	// SkipEmpty keeps a package with no data out of the cache.
	SkipEmpty bool
}

// Set is the enrichers and the connections they hold.
type Set struct {
	Specs []Spec
	conns []*grpc.ClientConn
}

// Close closes the connections.
func (s *Set) Close() error {
	var errs []error
	for _, c := range s.conns {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// Build connects to the services and returns the enrichers. It does not
// call the network: gRPC connects on the first call.
func Build(o Options) (*Set, error) {
	ep := client.Endpoint{URL: o.CommunityURL}
	if o.Credentials != nil && !o.Credentials.Anonymous() {
		key, err := o.Credentials.Credentials.GetAPIKey()
		if err != nil {
			return nil, err
		}
		ep = client.Endpoint{URL: o.APIURL, APIKey: key, Tenant: o.Credentials.TenantDomain()}
	}
	conn, err := client.Dial("vet-enrichers", ep)
	if err != nil {
		return nil, err
	}
	set := &Set{
		Specs: []Spec{
			{Name: insights.Name, Version: insights.Version, TTL: o.TTL, Plugin: insights.New(insightsv2grpc.NewInsightServiceClient(conn), o.Workers)},
			{
				Name: malysis.Name, Version: malysis.Version, TTL: min(o.TTL, malysis.MaxTTL), SkipEmpty: true,
				Plugin: malysis.New(malysisv1grpc.NewMalwareAnalysisServiceClient(conn), o.Workers),
			},
		},
		conns: []*grpc.ClientConn{conn},
	}
	if o.ActionRefs != nil {
		// A pin with no data is not cached, so a later scan checks it again.
		set.Specs = append(set.Specs, Spec{Name: actionrefs.Name, Version: o.ActionRefs.CacheVersion(), TTL: o.TTL, Plugin: o.ActionRefs, SkipEmpty: true})
	}
	if o.CodeUsageDir != "" {
		// The usage depends on the target, so the cache keeps none.
		set.Specs = append(set.Specs, Spec{Name: codeusage.Name, Version: codeusage.Version, Plugin: codeusage.New(o.CodeUsageDir, o.CodeUsage), Local: true})
	}
	return set, nil
}

// probePackage is a package that every SafeDep service knows.
var probePackage = model.MustPackageVersion(model.EcosystemNpm, "lodash", "4.17.21")

// Probe asks each enricher about one package, to check that its service
// answers. A package that the service does not know is an answer too. It
// returns the error of each enricher by name, or nil.
func (s *Set) Probe(ctx context.Context) map[string]error {
	out := map[string]error{}
	for _, sp := range s.Specs {
		if sp.Local {
			continue
		}
		out[sp.Name] = sp.Plugin.Enrich(ctx, []*model.Package{{ID: probePackage}})
	}
	return out
}
