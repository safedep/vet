// Package enrichers builds the SafeDep enrichers of a scan: Insights v2
// and Malysis. With no credentials, both call the community service. With
// an API key, both call the API service of the tenant.
package enrichers

import (
	"errors"
	"time"

	insightsv2grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/insights/v2/insightsv2grpc"
	malysisv1grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	"google.golang.org/grpc"

	"github.com/safedep/vet/v2/internal/credentials"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/insights"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/internal/client"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/malysis"
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
}

// Spec is one enricher with its cache identity.
type Spec struct {
	Name    string
	Version string
	TTL     time.Duration
	Plugin  plugin.Enricher
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
	return &Set{
		Specs: []Spec{
			{Name: insights.Name, Version: insights.Version, TTL: o.TTL, Plugin: insights.New(insightsv2grpc.NewInsightServiceClient(conn), o.Workers)},
			{Name: malysis.Name, Version: malysis.Version, TTL: o.TTL, Plugin: malysis.New(malysisv1grpc.NewMalwareAnalysisServiceClient(conn), o.Workers)},
		},
		conns: []*grpc.ClientConn{conn},
	}, nil
}
