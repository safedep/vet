package reporter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	drygrpc "github.com/safedep/dry/adapters/grpc"
	"github.com/safedep/dry/utils"
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

	headers := http.Header{}
	headers.Set("x-tenant-id", "default-team.safedep-io.safedep.io")
	headers.Set("x-mock-user", "abhisek@safedep.io")

	client, err := drygrpc.GrpcClient("vet-sync", host, port,
		config.ControlTowerToken, headers, []grpc.DialOption{})
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	trigger := controltowerv1.ToolTrigger_TOOL_TRIGGER_MANUAL
	source := controltowerv1.ProjectSource_PROJECT_SOURCE_OTHER

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

	return nil
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
	return nil
}

func validateSyncReporterConfig(config *SyncReporterConfig) error {
	if utils.IsEmptyString(config.ProjectName) {
		return errors.New("project name not in config")
	}

	if utils.IsEmptyString(config.ProjectVersion) {
		return errors.New("stream name not in config")
	}

	if utils.IsEmptyString(config.TriggerEvent) {
		return errors.New("trigger event not in config")
	}

	return nil
}
