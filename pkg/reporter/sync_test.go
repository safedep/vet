package reporter

import (
	"context"
	"errors"
	"testing"

	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

// MockToolServiceClient is a mock implementation of the ToolServiceClient interface
type MockToolServiceClient struct {
	mock.Mock
}

func (m *MockToolServiceClient) CreateToolSession(
	ctx context.Context,
	in *controltowerv1.CreateToolSessionRequest,
	opts ...grpc.CallOption,
) (*controltowerv1.CreateToolSessionResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*controltowerv1.CreateToolSessionResponse), args.Error(
		1,
	)
}

func (m *MockToolServiceClient) CompleteToolSession(
	ctx context.Context,
	in *controltowerv1.CompleteToolSessionRequest,
	opts ...grpc.CallOption,
) (*controltowerv1.CompleteToolSessionResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*controltowerv1.CompleteToolSessionResponse), args.Error(
		1,
	)
}

func (m *MockToolServiceClient) PublishPackageInsight(
	ctx context.Context,
	in *controltowerv1.PublishPackageInsightRequest,
	opts ...grpc.CallOption,
) (*controltowerv1.PublishPackageInsightResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*controltowerv1.PublishPackageInsightResponse), args.Error(
		1,
	)
}

func (m *MockToolServiceClient) PublishPolicyViolation(
	ctx context.Context,
	in *controltowerv1.PublishPolicyViolationRequest,
	opts ...grpc.CallOption,
) (*controltowerv1.PublishPolicyViolationResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*controltowerv1.PublishPolicyViolationResponse), args.Error(
		1,
	)
}

// MockCallbacks implements SyncReporterCallbacks for testing
type MockCallbacks struct {
	mock.Mock
}

func (m *MockCallbacks) OnSyncStart() {
	m.Called()
}

func (m *MockCallbacks) OnSyncFinish() {
	m.Called()
}

func (m *MockCallbacks) OnPackageSync(pkg *models.Package) {
	m.Called(pkg)
}

func (m *MockCallbacks) OnPackageSyncDone(pkg *models.Package) {
	m.Called(pkg)
}

func (m *MockCallbacks) OnEventSync(event *analyzer.AnalyzerEvent) {
	m.Called(event)
}

func (m *MockCallbacks) OnEventSyncDone(event *analyzer.AnalyzerEvent) {
	m.Called(event)
}

// mockDependencyGraph creates a simple dependency graph for testing
func mockDependencyGraph(pkg *models.Package) {
	// Create an empty dependency graph
	dg := models.NewDependencyGraph[*models.Package]()
	dg.SetPresent(true)

	// Add the package as root node
	dg.AddRootNode(pkg)

	// Set the dependency graph in the manifest
	pkg.Manifest.DependencyGraph = dg
}

func TestSyncPackage(t *testing.T) {
	tests := []struct {
		name          string
		pkg           *models.Package
		sessionID     string
		publishError  error
		expectedError bool
	}{
		{
			name: "successful sync",
			pkg: &models.Package{
				PackageDetails: lockfile.PackageDetails{
					Name:      "test-package",
					Version:   "1.0.0",
					Ecosystem: lockfile.Ecosystem("npm"),
				},
				Manifest: &models.PackageManifest{
					Path:      "path/to/manifest",
					Ecosystem: "npm",
					Source: models.PackageManifestSource{
						Namespace: "test-namespace",
					},
				},
			},
			sessionID:     "test-session-id",
			publishError:  nil,
			expectedError: false,
		},
		{
			name: "package with insights",
			pkg: &models.Package{
				PackageDetails: lockfile.PackageDetails{
					Name:      "package-with-insights",
					Version:   "2.0.0",
					Ecosystem: lockfile.Ecosystem("npm"),
				},
				Manifest: &models.PackageManifest{
					Path:      "path/to/manifest2",
					Ecosystem: "npm",
					Source: models.PackageManifestSource{
						Namespace: "test-namespace",
					},
				},
				InsightsV2: &packagev1.PackageVersionInsight{
					Vulnerabilities: []*vulnerabilityv1.Vulnerability{
						{
							Id: &vulnerabilityv1.VulnerabilityIdentifier{
								Value: "CVE-2022-1234",
								Type:  vulnerabilityv1.VulnerabilityIdentifierType_VULNERABILITY_IDENTIFIER_TYPE_CVE,
							},
							Summary: "Test vulnerability",
						},
					},
					Licenses: &packagev1.LicenseMetaList{
						Licenses: []*packagev1.LicenseMeta{
							{
								LicenseId: "MIT",
								Name:      "MIT License",
							},
						},
					},
				},
				MalwareAnalysis: &models.MalwareAnalysisResult{
					AnalysisId:   "analysis-123",
					IsMalware:    true,
					IsSuspicious: true,
				},
			},
			sessionID:     "test-session-id",
			publishError:  nil,
			expectedError: false,
		},
		{
			name: "package with detailed malware analysis",
			pkg: &models.Package{
				PackageDetails: lockfile.PackageDetails{
					Name:      "malware-package",
					Version:   "3.0.0",
					Ecosystem: lockfile.Ecosystem("npm"),
				},
				Manifest: &models.PackageManifest{
					Path:      "path/to/manifest3",
					Ecosystem: "npm",
					Source: models.PackageManifestSource{
						Namespace: "test-namespace",
					},
				},
				MalwareAnalysis: &models.MalwareAnalysisResult{
					AnalysisId:   "malware-analysis-456",
					IsMalware:    true,
					IsSuspicious: true,
					VerificationRecord: &malysisv1.VerificationRecord{
						Purl:      "pkg:npm/malware-package@3.0.0",
						IsMalware: true,
						Reason:    "Verified as malware by security team",
					},
					Report: &malysisv1.Report{
						Inference: &malysisv1.Report_Inference{
							Summary: "Suspicious code detected that attempts to exfiltrate sensitive data",
						},
					},
				},
			},
			sessionID:     "test-session-id",
			publishError:  nil,
			expectedError: false,
		},
		{
			name: "publish error",
			pkg: &models.Package{
				PackageDetails: lockfile.PackageDetails{
					Name:      "test-package",
					Version:   "1.0.0",
					Ecosystem: lockfile.Ecosystem("npm"),
				},
				Manifest: &models.PackageManifest{
					Path:      "path/to/manifest",
					Ecosystem: "npm",
					Source: models.PackageManifestSource{
						Namespace: "test-namespace",
					},
				},
			},
			sessionID:     "test-session-id",
			publishError:  errors.New("publish error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockClient := &MockToolServiceClient{}
			mockCallbacks := SyncReporterCallbacks{
				OnPackageSyncDone: func(pkg *models.Package) {},
			}

			// Create a dependency graph for the package to avoid warnings
			mockDependencyGraph(tt.pkg)

			// Setup response
			publishResponse := &controltowerv1.PublishPackageInsightResponse{}

			// Setup expectations
			mockClient.On("PublishPackageInsight", mock.Anything, mock.MatchedBy(func(req *controltowerv1.PublishPackageInsightRequest) bool {
				match := req.PackageVersion.Package.Name == tt.pkg.Name &&
					req.PackageVersion.Version == tt.pkg.Version &&
					req.ToolSession.ToolSessionId == tt.sessionID &&
					req.Manifest.Ecosystem == tt.pkg.Manifest.GetControlTowerSpecEcosystem() &&
					req.Manifest.Name == tt.pkg.Manifest.GetDisplayPath()

				// Additional checks for the malware insights case
				if tt.pkg.MalwareAnalysis != nil {
					match = match && req.MaliciousPackageInsight != nil &&
						req.MaliciousPackageInsight.AnalysisId == tt.pkg.MalwareAnalysis.AnalysisId &&
						req.MaliciousPackageInsight.IsMalware == tt.pkg.MalwareAnalysis.IsMalware

					// Check verification status
					isVerified := tt.pkg.MalwareAnalysis.VerificationRecord != nil
					match = match &&
						req.MaliciousPackageInsight.IsVerified == isVerified

					// Check summary if available
					if tt.pkg.MalwareAnalysis.Report != nil &&
						tt.pkg.MalwareAnalysis.Report.GetInference() != nil {
						match = match &&
							req.MaliciousPackageInsight.Summary == tt.pkg.MalwareAnalysis.Report.GetInference().
								GetSummary()
					}
				}

				return match
			})).Return(publishResponse, tt.publishError)

			// Setup reporter
			reporter := &syncReporter{
				config: &SyncReporterConfig{},
				sessions: &syncSessionPool{
					syncSessions: map[string]syncSession{
						tt.pkg.Manifest.Path: {
							sessionId:         tt.sessionID,
							toolServiceClient: mockClient,
						},
					},
				},
				callbacks: mockCallbacks,
			}

			// Initialize WaitGroup before calling syncPackage
			reporter.wg.Add(1)

			// Test the function
			err := reporter.syncPackage(tt.pkg)

			// Verify the results
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify all expectations
			mockClient.AssertExpectations(t)
		})
	}
}

func TestSyncSessionPool(t *testing.T) {
	mockClient := &MockToolServiceClient{}

	tests := []struct {
		name           string
		setupPool      func() *syncSessionPool
		key            string
		expectedResult bool
		expectedError  bool
	}{
		{
			name: "primary session exists",
			setupPool: func() *syncSessionPool {
				pool := &syncSessionPool{
					syncSessions: make(map[string]syncSession),
				}
				pool.addPrimarySession("primary-session", mockClient)
				return pool
			},
			key:            "any-key",
			expectedResult: true,
			expectedError:  false,
		},
		{
			name: "keyed session exists",
			setupPool: func() *syncSessionPool {
				pool := &syncSessionPool{
					syncSessions: make(map[string]syncSession),
				}
				pool.addKeyedSession(
					"specific-key",
					"specific-session",
					mockClient,
				)
				return pool
			},
			key:            "specific-key",
			expectedResult: true,
			expectedError:  false,
		},
		{
			name: "session does not exist",
			setupPool: func() *syncSessionPool {
				pool := &syncSessionPool{
					syncSessions: make(map[string]syncSession),
				}
				pool.addKeyedSession("existing-key", "some-session", mockClient)
				return pool
			},
			key:            "non-existent-key",
			expectedResult: false,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := tt.setupPool()

			session, err := pool.getSession(tt.key)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, session)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, session)
			}

			// Check if hasKeyedSession returns expected result
			if tt.key != "any-key" { // Skip for primary session test
				hasKey := pool.hasKeyedSession(tt.key)
				assert.Equal(
					t,
					tt.expectedResult && tt.key != "any-key",
					hasKey,
				)
			}
		})
	}
}

func TestSyncSessionPoolForEach(t *testing.T) {
	mockClient := &MockToolServiceClient{}

	pool := &syncSessionPool{
		syncSessions: make(map[string]syncSession),
	}

	// Add multiple sessions
	pool.addKeyedSession("key1", "session1", mockClient)
	pool.addKeyedSession("key2", "session2", mockClient)
	pool.addKeyedSession("key3", "session3", mockClient)

	// Test forEach with success callback
	processedKeys := map[string]bool{}
	processedSessions := map[string]bool{}

	err := pool.forEach(func(key string, session *syncSession) error {
		processedKeys[key] = true
		processedSessions[session.sessionId] = true
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 3, len(processedKeys))
	assert.True(t, processedKeys["key1"])
	assert.True(t, processedKeys["key2"])
	assert.True(t, processedKeys["key3"])
	assert.True(t, processedSessions["session1"])
	assert.True(t, processedSessions["session2"])
	assert.True(t, processedSessions["session3"])

	// Test forEach with error callback - this test needs to be modified
	// since map iteration order is not guaranteed in Go
	errorKey := "key2"
	processedAny := false

	err = pool.forEach(func(key string, session *syncSession) error {
		processedAny = true
		if key == errorKey {
			return errors.New("test error")
		}
		return nil
	})

	// We should have processed at least one key
	assert.True(t, processedAny)
	// And we should have an error
	assert.Error(t, err)
	assert.Equal(t, "test error", err.Error())
}

func TestSyncEvent(t *testing.T) {
	tests := []struct {
		name          string
		event         *analyzer.AnalyzerEvent
		sessionID     string
		publishError  error
		expectedError bool
	}{
		{
			name: "successful event sync",
			event: &analyzer.AnalyzerEvent{
				Package: &models.Package{
					PackageDetails: lockfile.PackageDetails{
						Name:      "test-package",
						Version:   "1.0.0",
						Ecosystem: lockfile.Ecosystem("npm"),
					},
					Manifest: &models.PackageManifest{
						Path:      "path/to/manifest",
						Ecosystem: "npm",
						Source: models.PackageManifestSource{
							Namespace: "test-namespace",
						},
					},
				},
				Filter: &filtersuite.Filter{
					CheckType: checks.CheckType_CheckTypeVulnerability,
					Name:      "test-vulnerability",
					Value:     "CVE-2023-1234",
					Summary:   "Test vulnerability for testing",
				},
			},
			sessionID:     "test-session-id",
			publishError:  nil,
			expectedError: false,
		},
		{
			name: "publish error",
			event: &analyzer.AnalyzerEvent{
				Package: &models.Package{
					PackageDetails: lockfile.PackageDetails{
						Name:      "test-package",
						Version:   "1.0.0",
						Ecosystem: lockfile.Ecosystem("npm"),
					},
					Manifest: &models.PackageManifest{
						Path:      "path/to/manifest",
						Ecosystem: "npm",
						Source: models.PackageManifestSource{
							Namespace: "test-namespace",
						},
					},
				},
				Filter: &filtersuite.Filter{
					CheckType: checks.CheckType_CheckTypeVulnerability,
					Name:      "test-vulnerability",
					Value:     "CVE-2023-1234",
					Summary:   "Test vulnerability for testing",
				},
			},
			sessionID:     "test-session-id",
			publishError:  errors.New("publish error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockClient := &MockToolServiceClient{}
			mockCallbacks := SyncReporterCallbacks{
				OnEventSyncDone: func(event *analyzer.AnalyzerEvent) {},
			}

			// Create a dependency graph for the package
			mockDependencyGraph(tt.event.Package)

			// Setup response
			publishResponse := &controltowerv1.PublishPolicyViolationResponse{}

			// Setup expectations
			mockClient.On("PublishPolicyViolation", mock.Anything, mock.MatchedBy(func(req *controltowerv1.PublishPolicyViolationRequest) bool {
				return req.PackageVersion.Package.Name == tt.event.Package.Name &&
					req.PackageVersion.Version == tt.event.Package.Version &&
					req.ToolSession.ToolSessionId == tt.sessionID &&
					req.Violation.Rule.Name == tt.event.Filter.GetName() &&
					req.Violation.Rule.Value == tt.event.Filter.GetValue()
			})).Return(publishResponse, tt.publishError)

			// Setup reporter
			reporter := &syncReporter{
				config: &SyncReporterConfig{},
				sessions: &syncSessionPool{
					syncSessions: map[string]syncSession{
						tt.event.Package.Manifest.Path: {
							sessionId:         tt.sessionID,
							toolServiceClient: mockClient,
						},
					},
				},
				callbacks: mockCallbacks,
			}

			// Initialize WaitGroup before calling syncEvent
			reporter.wg.Add(1)

			// Test the function
			err := reporter.syncEvent(tt.event)

			// Verify the results
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Verify all expectations
			mockClient.AssertExpectations(t)
		})
	}
}
