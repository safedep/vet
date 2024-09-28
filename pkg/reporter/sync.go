package reporter

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	drygrpc "github.com/safedep/dry/adapters/grpc"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/readers"
	"google.golang.org/grpc"
)

const (
	syncReporterDefaultWorkerCount = 10
	syncReporterMaxRetries         = 3
	syncReporterToolName           = "vet"
)

type SyncReporterConfig struct {
	// ControlTower API Base URL
	ControlTowerBaseUrl string
	ControlTowerToken   string

	// Required
	ProjectName    string
	ProjectVersion string
	TriggerEvent   string

	// Optional or auto-discovered from environment
	GitRef     string
	GitRefName string
	GitRefType string
	GitSha     string

	// Performance
	WorkerCount int

	// Tool details
	ToolName    string
	ToolVersion string
}

type syncReporter struct {
	config            *SyncReporterConfig
	workQueue         chan *models.Package
	done              chan bool
	wg                sync.WaitGroup
	client            *grpc.ClientConn
	toolServiceClient controltowerv1grpc.ToolServiceClient
	sessionId         string
}

func NewSyncReporter(config SyncReporterConfig) (Reporter, error) {
	parsedUrl, err := url.Parse(config.ControlTowerBaseUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ControlTower base URL: %w", err)
	}

	host, port := parsedUrl.Hostname(), parsedUrl.Port()
	if port == "" {
		port = "443"
	}

	logger.Debugf("ControlTower host: %s, port: %s", host, port)

	vetTenantId := os.Getenv("VET_CONTROL_TOWER_TENANT_ID")
	vetTenantMockUser := os.Getenv("VET_CONTROL_TOWER_MOCK_USER") // Used in dev

	headers := http.Header{}
	headers.Set("x-tenant-id", vetTenantId)
	headers.Set("x-mock-user", vetTenantMockUser)

	client, err := drygrpc.GrpcClient("vet-sync", host, port,
		config.ControlTowerToken, headers, []grpc.DialOption{})
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	trigger := controltowerv1.ToolTrigger_TOOL_TRIGGER_MANUAL
	source := packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_UNSPECIFIED

	logger.Debugf("Report Sync: Creating tool session for project: %s, version: %s",
		config.ProjectName, config.ProjectVersion)

	toolServiceClient := controltowerv1grpc.NewToolServiceClient(client)
	toolSessionRes, err := toolServiceClient.CreateToolSession(context.Background(),
		&controltowerv1.CreateToolSessionRequest{
			ToolName:       config.ToolName,
			ToolVersion:    config.ToolVersion,
			ProjectName:    config.ProjectName,
			ProjectVersion: &config.ProjectVersion,
			ProjectSource:  &source,
			Trigger:        &trigger,
		})
	if err != nil {
		return nil, fmt.Errorf("failed to create tool session: %w", err)
	}

	logger.Debugf("Report Sync: Tool data upload session ID: %s",
		toolSessionRes.GetToolSession().GetToolSessionId())

	done := make(chan bool)
	self := &syncReporter{
		config:            &config,
		done:              done,
		workQueue:         make(chan *models.Package, 1000),
		client:            client,
		toolServiceClient: toolServiceClient,
		sessionId:         toolSessionRes.GetToolSession().GetToolSessionId(),
	}

	self.startWorkers()
	return self, nil
}

func (s *syncReporter) Name() string {
	return "Cloud Sync Reporter"
}

func (s *syncReporter) AddManifest(manifest *models.PackageManifest) {
	// We are ignoring the error here because we are asynchronously handling the sync of Manifest
	_ = readers.NewManifestModelReader(manifest).EnumPackages(func(pkg *models.Package) error {
		s.queuePackage(pkg)
		return nil
	})
}

func (s *syncReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
}

func (s *syncReporter) AddPolicyEvent(event *policy.PolicyEvent) {
}

func (s *syncReporter) Finish() error {
	s.wg.Wait()
	close(s.done)

	logger.Debugf("Report Sync: Completing tool session: %s", s.sessionId)

	_, err := s.toolServiceClient.CompleteToolSession(context.Background(),
		&controltowerv1.CompleteToolSessionRequest{
			ToolSession: &controltowerv1.ToolSession{
				ToolSessionId: s.sessionId,
			},

			Status: controltowerv1.CompleteToolSessionRequest_STATUS_SUCCESS,
		})

	return err
}

func (s *syncReporter) queuePackage(pkg *models.Package) {
	s.wg.Add(1)
	s.workQueue <- pkg
}

func (s *syncReporter) startWorkers() {
	count := s.config.WorkerCount
	if count == 0 {
		count = syncReporterDefaultWorkerCount
	}

	for i := 0; i < count; i++ {
		go s.syncReportWorker()
	}
}

func (s *syncReporter) syncReportWorker() {
	for {
		select {
		case pkg := <-s.workQueue:
			err := s.syncPackage(pkg)
			if err != nil {
				logger.Errorf("failed to sync package: %v", err)
			}
		case <-s.done:
			return
		}
	}
}

func (s *syncReporter) syncPackage(pkg *models.Package) error {
	defer s.wg.Done()

	req := controltowerv1.PublishPackageInsightRequest{
		ToolSession: &controltowerv1.ToolSession{
			ToolSessionId: s.sessionId,
		},

		Manifest: &packagev1.PackageManifest{
			Ecosystem: pkg.Manifest.GetControlTowerSpecEcosystem(),
			Name:      pkg.Manifest.GetDisplayPath(),
		},

		PackageVersion: &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Ecosystem: pkg.Manifest.GetControlTowerSpecEcosystem(),
				Name:      pkg.Name,
			},

			Version: pkg.Version,
		},

		PackageVersionInsight: &packagev1.PackageVersionInsight{
			Dependencies: []*packagev1.PackageVersion{},
		},
	}

	dependencies, err := pkg.GetDependencies()
	if err != nil {
		logger.Warnf("failed to get dependencies for package: %s/%s/%s: %s",
			pkg.Manifest.Ecosystem, pkg.GetName(), pkg.GetVersion(), err.Error())
	} else {
		for _, child := range dependencies {
			req.PackageVersionInsight.Dependencies = append(req.PackageVersionInsight.Dependencies, &packagev1.PackageVersion{
				Package: &packagev1.Package{
					Ecosystem: child.Manifest.GetControlTowerSpecEcosystem(),
					Name:      child.GetName(),
				},

				Version: child.GetVersion(),
			})
		}
	}

	_, err = s.toolServiceClient.PublishPackageInsight(context.Background(), &req)
	if err != nil {
		return fmt.Errorf("failed to publish package insight: %w", err)
	}

	return nil
}
