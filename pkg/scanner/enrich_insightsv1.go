package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gojek/heimdall"
	"github.com/gojek/heimdall/v7/hystrix"
	"github.com/safedep/dry/errors"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

type InsightsBasedPackageMetaEnricherConfig struct {
	ApiUrl     string
	ApiAuthKey string
}

type insightsBasedPackageEnricher struct {
	client *insightapi.ClientWithResponses
}

func NewInsightBasedPackageEnricher(config InsightsBasedPackageMetaEnricherConfig) (PackageMetaEnricher, error) {
	apiKeyApplier := func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", config.ApiAuthKey)
		return nil
	}

	timeout := 5 * time.Second
	backoff := heimdall.NewConstantBackoff(1*time.Second,
		3*time.Second)

	retriableClient := hystrix.NewClient(hystrix.WithHTTPTimeout(timeout),
		hystrix.WithCommandName("insights-api-client"),
		hystrix.WithMaxConcurrentRequests(10),
		hystrix.WithRetryCount(3),
		hystrix.WithRetrier(heimdall.NewRetrier(backoff)))

	client, err := insightapi.NewClientWithResponses(config.ApiUrl,
		insightapi.WithRequestEditorFn(apiKeyApplier),
		insightapi.WithHTTPClient(retriableClient))
	if err != nil {
		return nil, err
	}

	return &insightsBasedPackageEnricher{
		client: client,
	}, nil
}

func (e *insightsBasedPackageEnricher) Name() string {
	return "Insights API"
}

func (e *insightsBasedPackageEnricher) Enrich(pkg *models.Package,
	cb PackageDependencyCallbackFn) error {

	logger.Infof("[%s] Enriching %s/%s", pkg.Manifest.Ecosystem,
		pkg.PackageDetails.Name, pkg.PackageDetails.Version)

	res, err := e.client.GetPackageVersionInsightWithResponse(context.Background(),
		string(pkg.PackageDetails.Ecosystem),
		pkg.Name, pkg.Version)
	if err != nil {
		logger.Errorf("Failed to enrich package: %v", err)
		return err
	}

	if res.HTTPResponse.StatusCode != 200 {
		err, _ = errors.UnmarshalApiError(res.Body)
		return err
	}

	if res.JSON200 == nil {
		return fmt.Errorf("unexpected nil response for: %s/%s/%s",
			pkg.Manifest.Ecosystem, pkg.PackageDetails.Name, pkg.Insights.PackageVersion.Version)
	}

	for _, dep := range utils.SafelyGetValue(res.JSON200.Dependencies) {
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
			logger.Errorf("package dependency callback failed: %v", err)
		}
	}

	// We should acquire a lock before mutating package?
	pkg.Insights = res.JSON200
	return nil
}

func (e *insightsBasedPackageEnricher) Wait() error {
	return nil
}
