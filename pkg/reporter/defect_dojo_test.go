package reporter

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDefectDojoReporterFailFastOnMissingProduct(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && (r.URL.Path == "/api/v2/products/404" || r.URL.Path == "/api/v2/products/404/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"Not found"}`))
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	r, err := NewDefectDojoReporter(DefectDojoReporterConfig{
		Tool: ToolMetadata{
			Name:           "vet",
			Version:        "test",
			InformationURI: "https://github.com/safedep/vet",
		},
		IncludeVulns:       true,
		IncludeMalware:     true,
		ProductID:          404,
		EngagementName:     "test-engagement",
		DefectDojoHostUrl:  server.URL,
		DefectDojoApiV2Key: "test-key",
	})

	assert.ErrorContains(t, err, "couldn't get product information for product_id = 404")
	assert.Nil(t, r)
}

func TestDefectDojoReporterUsesProductValidatedInConstructor(t *testing.T) {
	var productGetCount atomic.Int32
	var importPostCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/api/v2/products/42" || r.URL.Path == "/api/v2/products/42/"):
			productGetCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":42,"name":"validated-product"}`))

		case r.Method == http.MethodPost && (r.URL.Path == "/api/v2/import-scan/" || r.URL.Path == "/api/v2/import-scan"):
			importPostCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"ok"}`))

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	reporter, err := NewDefectDojoReporter(DefectDojoReporterConfig{
		Tool: ToolMetadata{
			Name:           "vet",
			Version:        "test",
			InformationURI: "https://github.com/safedep/vet",
		},
		IncludeVulns:       true,
		IncludeMalware:     true,
		ProductID:          42,
		EngagementName:     "test-engagement",
		DefectDojoHostUrl:  server.URL,
		DefectDojoApiV2Key: "test-key",
	})
	require.NoError(t, err)
	require.NotNil(t, reporter)

	typedReporter, ok := reporter.(*defectDojoReporter)
	require.True(t, ok)
	assert.Equal(t, "validated-product", typedReporter.productName)

	require.NoError(t, reporter.Finish())
	assert.Equal(t, int32(1), productGetCount.Load(), "product should be validated only in constructor")
	assert.Equal(t, int32(1), importPostCount.Load())
}
