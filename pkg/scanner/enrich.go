package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

// Callback to receive a discovery package dependency
type PackageDependencyCallbackFn func(pkg *models.Package) error

// Enrich meta information associated with
// the package
type PackageMetaEnricher interface {
	Name() string
	Enrich(pkg *models.Package, cb PackageDependencyCallbackFn) error
}

type insightsBasedPackageEnricher struct {
	client *insightapi.ClientWithResponses
}

func NewInsightBasedPackageEnricher() PackageMetaEnricher {
	apiKeyApplier := func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", auth.ApiKey())
		return nil
	}

	client, err := insightapi.NewClientWithResponses(auth.ApiUrl(),
		insightapi.WithRequestEditorFn(apiKeyApplier))
	if err != nil {
		// TODO: Handle
		panic(err)
	}

	return &insightsBasedPackageEnricher{
		client: client,
	}
}

func (e *insightsBasedPackageEnricher) Name() string {
	return "Insights API"
}

func (e *insightsBasedPackageEnricher) Enrich(pkg *models.Package,
	cb PackageDependencyCallbackFn) error {

	logger.Infof("[%s] Enriching %s/%s", pkg.Manifest.Ecosystem,
		pkg.PackageDetails.Name, pkg.PackageDetails.Version)

	res, err := e.client.GetPackageVersionInsightWithResponse(context.Background(),
		pkg.Manifest.Ecosystem, pkg.Name, pkg.Version)
	if err != nil {
		logger.Errorf("Failed to enrich package: %v", err)
		return err
	}

	if res.HTTPResponse.StatusCode != 200 {
		return fmt.Errorf("bad response: %d: %s", res.HTTPResponse.StatusCode,
			res.HTTPResponse.Status)
	}

	if (res.JSON200 == nil) || (res.JSON200.Dependencies == nil) {
		return fmt.Errorf("unexpected nil response from Insight API")
	}

	for _, dep := range *res.JSON200.Dependencies {
		if strings.EqualFold(dep.PackageVersion.Name, pkg.PackageDetails.Name) {
			// Skip self references in dependency
			continue
		}

		err := cb(&models.Package{
			Manifest: pkg.Manifest,
			Parent:   pkg,
			Depth:    pkg.Depth + 1,
			PackageDetails: models.NewPackageDetail(dep.PackageVersion.Ecosystem,
				dep.PackageVersion.Name, dep.PackageVersion.Version),
		})

		if err != nil {
			logger.Errorf("Failed to invoke package dependency callback: %v", err)
		}
	}

	pkg.Insights = res.JSON200
	return nil
}
