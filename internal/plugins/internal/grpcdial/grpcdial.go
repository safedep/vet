// Package grpcdial connects the plugins to a SafeDep gRPC service: the
// enrichers and the cloud plugins.
package grpcdial

import (
	"fmt"
	"net/http"
	"net/url"

	drygrpc "github.com/safedep/dry/adapters/grpc"
	"google.golang.org/grpc"
)

// Endpoint is a SafeDep service and the credentials for it. An empty API key
// is an anonymous call.
type Endpoint struct {
	// URL is https://host[:port], or http://host:port for a stub.
	URL    string
	APIKey string
	Tenant string
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
	switch u.Scheme {
	case "http":
		if port == "" {
			port = "80"
		}
		return drygrpc.GrpcInsecureClient(name, u.Hostname(), port, e.APIKey, headers, nil, drygrpc.NoGrpcConfigurer)
	case "https":
		if port == "" {
			port = "443"
		}
		return drygrpc.GrpcSecureClient(name, u.Hostname(), port, e.APIKey, headers, nil)
	}
	return nil, fmt.Errorf("%s: endpoint %q needs https or http", name, e.URL)
}
