package stub

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	insightsv2grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/insights/v2/insightsv2grpc"
	malysisv1grpc "buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysismsg "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	insightsv2 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/insights/v2"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func start(t *testing.T) (*Server, *grpc.ClientConn) {
	t.Helper()
	s, err := Start("fixtures")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	conn, err := grpc.NewClient(strings.TrimPrefix(s.URL(), "http://"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	return s, conn
}

func npm(name, version string) *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM, Name: name},
		Version: version,
	}
}

func TestInsights(t *testing.T) {
	s, conn := start(t)
	c := insightsv2grpc.NewInsightServiceClient(conn)
	ctx := context.Background()

	res, err := c.GetPackageVersionInsight(ctx, &insightsv2.GetPackageVersionInsightRequest{PackageVersion: npm("lodash", "4.17.21")})
	require.NoError(t, err)
	assert.Equal(t, "lodash", res.GetPackageVersion().GetPackage().GetName())

	_, err = c.GetPackageVersionInsight(ctx, &insightsv2.GetPackageVersionInsightRequest{PackageVersion: npm("unknown", "1.0.0")})
	assert.Equal(t, codes.NotFound, status.Code(err))

	s.Fail(Insights, codes.Unavailable)
	_, err = c.GetPackageVersionInsight(ctx, &insightsv2.GetPackageVersionInsightRequest{PackageVersion: npm("lodash", "4.17.21")})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Equal(t, 3, s.Calls(Insights))
}

func TestMalysis(t *testing.T) {
	s, conn := start(t)
	c := malysisv1grpc.NewMalwareAnalysisServiceClient(conn)
	ctx := context.Background()
	query := func(pv *packagev1.PackageVersion) *malysisv1.QueryPackageAnalysisResponse {
		res, err := c.QueryPackageAnalysis(ctx, &malysisv1.QueryPackageAnalysisRequest{Target: &malysismsg.PackageAnalysisTarget{PackageVersion: pv}})
		require.NoError(t, err)
		return res
	}

	assert.True(t, query(npm("safedep-test-pkg", "0.1.3")).GetReport().GetInference().GetIsMalware())
	clean := query(npm("lodash", "4.17.21"))
	assert.False(t, clean.GetReport().GetInference().GetIsMalware())
	assert.Equal(t, malysisv1.AnalysisStatus_ANALYSIS_STATUS_COMPLETED, clean.GetStatus())

	s.SetDelay(50 * time.Millisecond)
	start := time.Now()
	query(npm("lodash", "4.17.21"))
	assert.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
	assert.Equal(t, 3, s.Calls(Malysis))
}

func TestGitHub(t *testing.T) {
	s, _ := start(t)
	get := func(path, accept string) (int, string) {
		req, err := http.NewRequest(http.MethodGet, s.URL()+path, nil)
		require.NoError(t, err)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func() { require.NoError(t, res.Body.Close()) }()
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		return res.StatusCode, string(b)
	}
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"

	cases := []struct {
		name, path, accept string
		code               int
		body               string
	}{
		{name: "tag ref", path: "/repos/actions/checkout/git/ref/tags/v4", code: 200, body: `"sha":"` + sha},
		{name: "branch ref", path: "/api/v3/repos/actions/checkout/git/ref/heads/main", code: 200, body: `"ref":"refs/heads/main"`},
		{name: "commit sha", path: "/repos/actions/checkout/commits/v4", accept: "application/vnd.github.sha", code: 200, body: sha},
		{name: "unknown tag", path: "/repos/actions/checkout/git/ref/tags/v9", code: 404},
		{name: "unknown repo", path: "/repos/nobody/nothing/commits/v1", code: 404},
		{name: "releases", path: "/api/v3/repos/safedep/vet/releases", code: 200, body: `{"tag_name":"v2.0.0-alpha.20260102000000","immutable":true,"published_at":"2026-01-01T00:00:00Z"}`},
		{name: "releases of an unknown repo", path: "/repos/nobody/nothing/releases", code: 404},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := get(tc.path, tc.accept)
			assert.Equal(t, tc.code, code)
			assert.Contains(t, body, tc.body)
		})
	}

	s.Fail(GitHub, codes.Unavailable)
	code, _ := get("/repos/actions/checkout/git/ref/tags/v4", "")
	assert.Equal(t, http.StatusServiceUnavailable, code)
}
