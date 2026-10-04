// Package client holds what the SafeDep enrichers share: the gRPC
// connection, the ecosystem mapping and the worker pool.
package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	drygrpc "github.com/safedep/dry/adapters/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// Endpoint is a SafeDep service and the credentials for it. An empty API key
// is an anonymous call to the community service.
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

// ErrNoEcosystem means that the SafeDep services do not take the ecosystem.
var ErrNoEcosystem = errors.New("the SafeDep API has no ecosystem for the package")

// gap G2: the SafeDep API has ECOSYSTEM_PUB, but the services validate the
// ecosystem against an older SDK and reject it. Pub packages get no
// enrichment until the services run on the new SDK.
var notServed = map[model.Ecosystem]bool{model.EcosystemPub: true}

// PackageVersion returns the wire form of a package: the raw name and
// version, as the manifest writes them. The service folds them under its own
// rule.
func PackageVersion(id model.PackageVersion) (*packagev1.PackageVersion, error) {
	if notServed[id.Ecosystem()] {
		return nil, fmt.Errorf("%w: %s", ErrNoEcosystem, id.Ecosystem())
	}
	return id.RawProto(), nil
}

// Unavailable reports a gRPC error of a backend that does not answer.
func Unavailable(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted:
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// packageError is the error of a backend call for one package. A person
// reads it as a diagnostic, so a gRPC error gets a short text in place of
// the status dump.
type packageError struct {
	ID  model.PackageVersion
	Err error
}

func (e *packageError) Error() string {
	s, ok := status.FromError(e.Err)
	if !ok {
		return fmt.Sprintf("%s: %v", e.ID, e.Err)
	}
	return fmt.Sprintf("The backend did not answer for %s (%s).", e.ID, codeText(s.Code()))
}

func (e *packageError) Unwrap() error { return e.Err }

var codeTexts = map[codes.Code]string{
	codes.Canceled:           "cancelled",
	codes.Unknown:            "unknown error",
	codes.InvalidArgument:    "invalid request",
	codes.AlreadyExists:      "conflict",
	codes.PermissionDenied:   "permission denied",
	codes.FailedPrecondition: "invalid request",
	codes.OutOfRange:         "invalid request",
	codes.Unimplemented:      "not supported",
	codes.Internal:           "internal error",
	codes.DataLoss:           "internal error",
	codes.Unauthenticated:    "API key not accepted",
}

func codeText(c codes.Code) string {
	if t, ok := codeTexts[c]; ok {
		return t
	}
	return strings.ToLower(c.String())
}

// Each calls fn for each package with at most workers calls at once. A
// NotFound answer and a package with no API ecosystem are no data. When the
// backend does not answer, Each returns an error that wraps
// plugin.ErrUnavailable. It returns the first other error.
func Each(ctx context.Context, workers int, pkgs []*model.Package, fn func(context.Context, *model.Package) error) error {
	if workers <= 0 {
		workers = 8
	}
	var (
		mu          sync.Mutex
		firstErr    error
		unavailable bool
		wg          sync.WaitGroup
	)
	sem := make(chan struct{}, workers)
	for _, p := range pkgs {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			err := fn(ctx, p)
			if err == nil || status.Code(err) == codes.NotFound || errors.Is(err, ErrNoEcosystem) {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if Unavailable(err) {
				unavailable = true
				return
			}
			if firstErr == nil {
				firstErr = &packageError{ID: p.ID, Err: err}
			}
		}()
	}
	wg.Wait()
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case firstErr != nil:
		return firstErr
	case unavailable:
		return plugin.ErrUnavailable
	}
	return nil
}
