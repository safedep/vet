// Package grpcdial connects the plugins to a SafeDep gRPC service: the
// enrichers and the cloud plugins.
package grpcdial

import (
	"fmt"
	"net/http"
	"net/url"

	drygrpc "github.com/safedep/dry/adapters/grpc"
	"google.golang.org/grpc"
	grpccreds "google.golang.org/grpc/credentials"

	"github.com/safedep/vet/v2/internal/credentials"
)

// Endpoint is a SafeDep service and the credentials for it. An empty API key
// and no workload credential is an anonymous call.
type Endpoint struct {
	// URL is https://host[:port], or http://host:port for a stub.
	URL    string
	APIKey string
	Tenant string
	// Workload sends a workload credential and its tenant on each call, in
	// place of APIKey and Tenant.
	Workload grpccreds.PerRPCCredentials
}

// Cloud returns the endpoint of a SafeDep Cloud service with the
// credentials of the run: the API key and its tenant, or the workload
// credential.
func Cloud(url string, creds *credentials.Result) (Endpoint, error) {
	if w, ok := creds.Workload(); ok {
		return Endpoint{URL: url, Workload: w}, nil
	}
	key, err := creds.Credentials.GetAPIKey()
	if err != nil {
		return Endpoint{}, err
	}
	return Endpoint{URL: url, APIKey: key, Tenant: creds.TenantDomain()}, nil
}

// Dial connects to the endpoint. An http URL uses no TLS, for the stub
// server of the acceptance suite.
func Dial(name string, e Endpoint) (*grpc.ClientConn, error) {
	u, err := url.Parse(e.URL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("%s: bad endpoint %q", name, e.URL)
	}
	port := u.Port()
	headers := http.Header{}
	if e.Tenant != "" {
		headers.Set("x-tenant-id", e.Tenant)
	}
	var opts []grpc.DialOption
	switch u.Scheme {
	case "http":
		if port == "" {
			port = "80"
		}
		if e.Workload != nil {
			opts = append(opts, grpc.WithPerRPCCredentials(noTLSCredentials{e.Workload}))
		}
		return drygrpc.GrpcInsecureClient(name, u.Hostname(), port, e.APIKey, headers, opts, drygrpc.NoGrpcConfigurer)
	case "https":
		if port == "" {
			port = "443"
		}
		if e.Workload != nil {
			opts = append(opts, grpc.WithPerRPCCredentials(e.Workload))
		}
		return drygrpc.GrpcSecureClient(name, u.Hostname(), port, e.APIKey, headers, opts)
	}
	return nil, fmt.Errorf("%s: endpoint %q needs https or http", name, e.URL)
}

// noTLSCredentials sends a workload credential to the stub server, which
// has no TLS. gRPC refuses a credential that requires TLS on a connection
// without it.
type noTLSCredentials struct {
	grpccreds.PerRPCCredentials
}

func (noTLSCredentials) RequireTransportSecurity() bool { return false }
