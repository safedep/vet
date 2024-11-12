package scanner

import (
	"context"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/insights/v2/insightsv2grpc"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	insightsv2 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/insights/v2"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"google.golang.org/grpc"
)

type insightsBasedPackageEnricherV2 struct {
	cc     *grpc.ClientConn
	client insightsv2grpc.InsightServiceClient
}

// NewInsightBasedPackageEnricherV2 creates a new instance of the enricher using
// Insights API v2. It requires a pre-configured gRPC client connection.
func NewInsightBasedPackageEnricherV2(cc *grpc.ClientConn) (PackageMetaEnricher, error) {
	client := insightsv2grpc.NewInsightServiceClient(cc)
	return &insightsBasedPackageEnricherV2{
		cc:     cc,
		client: client,
	}, nil
}

func (e *insightsBasedPackageEnricherV2) Name() string {
	return "Insights API v2"
}

// Enrich will enrich the package using Insights V2 API. However, most of the
// analysers and reporters in vet are coupled with Insights V1 data model. Till
// we are able to drive a major refactor to decouple them, we need to convert V2
// data model to V1 data model while preserving the V2 data. This will ensure
//
// - Existing analysers and reporters continue to work without any changes.
// - We can start using V2 data model in new analysers and reporters.
func (e *insightsBasedPackageEnricherV2) Enrich(pkg *models.Package,
	cb PackageDependencyCallbackFn) error {
	res, err := e.client.GetPackageVersionInsight(context.Background(),
		&insightsv2.GetPackageVersionInsightRequest{
			PackageVersion: &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: pkg.GetControlTowerSpecEcosystem(),
					Name:      pkg.GetName(),
				},
				Version: pkg.GetVersion(),
			},
		})

	if err != nil {
		logger.Debugf("Failed to enrich package: %s/%s: %v",
			pkg.GetName(), pkg.GetVersion(), err)
		return err
	}

	return e.applyInsights(pkg, res)
}

func (e *insightsBasedPackageEnricherV2) applyInsights(pkg *models.Package,
	res *insightsv2.GetPackageVersionInsightResponse) error {
	return nil
}
