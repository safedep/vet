package reporter

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/checks"
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
	// gRPC connection for ControlTower
	ClientConnection *grpc.ClientConn

	// Enable multi-project syncing
	// In this case, a new project is created per package manifest
	EnableMultiProjectSync bool

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

type syncSession struct {
	sessionId         string
	toolServiceClient controltowerv1grpc.ToolServiceClient
}

type syncSessionPool struct {
	mu           sync.RWMutex
	syncSessions map[string]syncSession
}

// Only use this session
func (s *syncSessionPool) addPrimarySession(sessionId string, client controltowerv1grpc.ToolServiceClient) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.syncSessions["*"] = syncSession{
		sessionId:         sessionId,
		toolServiceClient: client,
	}
}

func (s *syncSessionPool) hasKeyedSession(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.syncSessions[key]
	return ok
}

func (s *syncSessionPool) addKeyedSession(key, sessionId string, client controltowerv1grpc.ToolServiceClient) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.syncSessions[key] = syncSession{
		sessionId:         sessionId,
		toolServiceClient: client,
	}
}

func (s *syncSessionPool) getSession(key string) (*syncSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s, ok := s.syncSessions["*"]; ok {
		return &s, nil
	}

	if s, ok := s.syncSessions[key]; ok {
		return &s, nil
	}

	return nil, fmt.Errorf("session not found for key: %s", key)
}

func (s *syncSessionPool) forEach(f func(key string, session *syncSession) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for key, session := range s.syncSessions {
		err := f(key, &session)
		if err != nil {
			return err
		}
	}

	return nil
}

type workItem struct {
	pkg   *models.Package
	event *analyzer.AnalyzerEvent
}

type syncReporter struct {
	config    *SyncReporterConfig
	workQueue chan *workItem
	done      chan bool
	wg        sync.WaitGroup
	client    *grpc.ClientConn
	sessions  *syncSessionPool
}

func NewSyncReporter(config SyncReporterConfig) (Reporter, error) {
	if config.ClientConnection == nil {
		return nil, fmt.Errorf("missing gRPC client connection")
	}

	// TODO: Auto-discover config using CI environment variables
	// if enabled by the user

	syncSessionPool := syncSessionPool{
		syncSessions: make(map[string]syncSession),
	}

	trigger := controltowerv1.ToolTrigger_TOOL_TRIGGER_MANUAL
	source := packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_UNSPECIFIED

	// A multi-project sync is required for cases like GitHub org where
	// we are scanning multiple repositories
	if !config.EnableMultiProjectSync {
		logger.Debugf("Report Sync: Creating tool session for project: %s, version: %s",
			config.ProjectName, config.ProjectVersion)

		// Refactor this into a common session creator function
		toolServiceClient := controltowerv1grpc.NewToolServiceClient(config.ClientConnection)
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

		syncSessionPool.addPrimarySession(toolSessionRes.GetToolSession().GetToolSessionId(),
			toolServiceClient)
	}

	done := make(chan bool)
	self := &syncReporter{
		config:    &config,
		done:      done,
		workQueue: make(chan *workItem, 1000),
		client:    config.ClientConnection,
		sessions:  &syncSessionPool,
	}

	self.startWorkers()
	return self, nil
}

func (s *syncReporter) Name() string {
	return "Cloud Sync Reporter"
}

func (s *syncReporter) AddManifest(manifest *models.PackageManifest) {
	manifestSessionKey := manifest.Path
	if s.config.EnableMultiProjectSync && !s.sessions.hasKeyedSession(manifestSessionKey) {
		projectName := manifest.GetSource().GetNamespace()
		projectVersion := "main"

		source := packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_UNSPECIFIED
		trigger := controltowerv1.ToolTrigger_TOOL_TRIGGER_MANUAL

		logger.Debugf("Report Sync: Creating tool session for project: %s, version: %s",
			projectName, projectVersion)

		// Refactor this into a common session creator function
		toolServiceClient := controltowerv1grpc.NewToolServiceClient(s.client)
		toolSessionRes, err := toolServiceClient.CreateToolSession(context.Background(),
			&controltowerv1.CreateToolSessionRequest{
				ToolName:       s.config.ToolName,
				ToolVersion:    s.config.ToolVersion,
				ProjectName:    projectName,
				ProjectVersion: &projectVersion,
				ProjectSource:  &source,
				Trigger:        &trigger,
			})
		if err != nil {
			logger.Errorf("failed to create tool session for project: %s/%s: %v",
				projectName, projectVersion, err)
		}

		logger.Debugf("Report Sync: Tool data upload session ID: %s",
			toolSessionRes.GetToolSession().GetToolSessionId())

		s.sessions.addKeyedSession(manifestSessionKey,
			toolSessionRes.GetToolSession().GetToolSessionId(), toolServiceClient)

	}

	// We are ignoring the error here because we are asynchronously handling the sync of Manifest
	_ = readers.NewManifestModelReader(manifest).EnumPackages(func(pkg *models.Package) error {
		s.queuePackage(pkg)
		return nil
	})
}

func (s *syncReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	s.queueEvent(event)
}

func (s *syncReporter) AddPolicyEvent(event *policy.PolicyEvent) {
}

func (s *syncReporter) Finish() error {
	s.wg.Wait()
	close(s.done)

	return s.sessions.forEach(func(_ string, session *syncSession) error {
		logger.Debugf("Report Sync: Completing tool session: %s", session.sessionId)

		_, err := session.toolServiceClient.CompleteToolSession(context.Background(),
			&controltowerv1.CompleteToolSessionRequest{
				ToolSession: &controltowerv1.ToolSession{
					ToolSessionId: session.sessionId,
				},

				Status: controltowerv1.CompleteToolSessionRequest_STATUS_SUCCESS,
			})

		return err
	})
}

func (s *syncReporter) queueEvent(event *analyzer.AnalyzerEvent) {
	s.wg.Add(1)
	s.workQueue <- &workItem{event: event}
}

func (s *syncReporter) queuePackage(pkg *models.Package) {
	s.wg.Add(1)
	s.workQueue <- &workItem{pkg: pkg}
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
		case item := <-s.workQueue:
			if item.event != nil {
				err := s.syncEvent(item.event)
				if err != nil {
					logger.Errorf("failed to sync event: %v", err)
				}
			} else if item.pkg != nil {
				err := s.syncPackage(item.pkg)
				if err != nil {
					logger.Errorf("failed to sync package: %v", err)
				}
			}
		case <-s.done:
			return
		}
	}
}

func (s *syncReporter) syncEvent(event *analyzer.AnalyzerEvent) error {
	defer s.wg.Done()

	pkg := event.Package
	filter := event.Filter

	if pkg == nil || filter == nil || pkg.Manifest == nil {
		return fmt.Errorf("failed to sync event: invalid event data")
	}

	manifestSessionKey := pkg.Manifest.Path
	session, err := s.sessions.getSession(manifestSessionKey)
	if err != nil {
		return fmt.Errorf("failed to get session for package: %s/%s/%s: %w",
			pkg.Manifest.Ecosystem, pkg.GetName(), pkg.GetVersion(), err)
	}

	checkType := policyv1.RuleCheck_RULE_CHECK_UNSPECIFIED
	switch filter.GetCheckType() {
	case checks.CheckType_CheckTypeVulnerability:
		checkType = policyv1.RuleCheck_RULE_CHECK_VULNERABILITY
	case checks.CheckType_CheckTypeLicense:
		checkType = policyv1.RuleCheck_RULE_CHECK_LICENSE
	case checks.CheckType_CheckTypeMalware:
		checkType = policyv1.RuleCheck_RULE_CHECK_MALWARE
	case checks.CheckType_CheckTypeMaintenance:
		checkType = policyv1.RuleCheck_RULE_CHECK_MAINTENANCE
	case checks.CheckType_CheckTypePopularity:
		checkType = policyv1.RuleCheck_RULE_CHECK_POPULARITY
	case checks.CheckType_CheckTypeSecurityScorecard:
		checkType = policyv1.RuleCheck_RULE_CHECK_PROJECT_SCORECARD
	default:
		logger.Warnf("unsupported check type: %s", filter.GetCheckType())
	}

	logger.Debugf("Report Sync: Publishing policy violation for package: %s/%s/%s/%s with violation %s/%s/%s",
		pkg.Manifest.GetControlTowerSpecEcosystem(), pkg.Manifest.GetDisplayPath(), pkg.GetName(), pkg.GetVersion(),
		checkType, filter.GetName(), filter.GetValue())

	namespace := pkg.Manifest.GetSource().GetNamespace()
	req := controltowerv1.PublishPolicyViolationRequest{
		ToolSession: &controltowerv1.ToolSession{
			ToolSessionId: session.sessionId,
		},

		Manifest: &packagev1.PackageManifest{
			Ecosystem: pkg.Manifest.GetControlTowerSpecEcosystem(),
			Namespace: &namespace,
			Name:      pkg.Manifest.GetDisplayPath(),
		},

		PackageVersion: &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Ecosystem: pkg.Manifest.GetControlTowerSpecEcosystem(),
				Name:      pkg.Name,
			},

			Version: pkg.Version,
		},

		Violation: &policyv1.Violation{
			Rule: &policyv1.Rule{
				Name:        filter.GetName(),
				Description: filter.GetSummary(),
				Value:       filter.GetValue(),
				Check:       checkType,
			},

			Evidences: []*policyv1.ViolationEvidence{},
		},
	}

	_, err = session.toolServiceClient.PublishPolicyViolation(context.Background(), &req)
	if err != nil {
		return fmt.Errorf("failed to publish policy violation: %w", err)
	}

	return nil
}

func (s *syncReporter) syncPackage(pkg *models.Package) error {
	defer s.wg.Done()

	manifestSessionKey := pkg.Manifest.Path
	session, err := s.sessions.getSession(manifestSessionKey)
	if err != nil {
		return fmt.Errorf("failed to get session for package: %s/%s/%s: %w",
			pkg.Manifest.Ecosystem, pkg.GetName(), pkg.GetVersion(), err)
	}

	logger.Debugf("Report Sync: Publishing package insight for package: %s/%s/%s/%s",
		pkg.Manifest.GetControlTowerSpecEcosystem(), pkg.Manifest.GetDisplayPath(), pkg.GetName(), pkg.GetVersion())

	namespace := pkg.Manifest.GetSource().GetNamespace()
	req := controltowerv1.PublishPackageInsightRequest{
		ToolSession: &controltowerv1.ToolSession{
			ToolSessionId: session.sessionId,
		},

		Manifest: &packagev1.PackageManifest{
			Ecosystem: pkg.Manifest.GetControlTowerSpecEcosystem(),
			Namespace: &namespace,
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
			Dependencies:    []*packagev1.PackageVersion{},
			Vulnerabilities: []*vulnerabilityv1.Vulnerability{},
			ProjectInsights: []*packagev1.ProjectInsight{},
			Licenses: &packagev1.LicenseMetaList{
				Licenses: []*packagev1.LicenseMeta{},
			},
		},
	}

	// Add package dependencies
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

	// Get the insights
	insights := utils.SafelyGetValue(pkg.Insights)

	// Add vulnerabilities. We will publish only the minimum required information.
	// The backend should have its own VDB to enrich the data.
	vulnerabilities := utils.SafelyGetValue(insights.Vulnerabilities)
	for _, v := range vulnerabilities {
		vId := utils.SafelyGetValue(v.Id)
		vulnerability := vulnerabilityv1.Vulnerability{
			Id: &vulnerabilityv1.VulnerabilityIdentifier{
				Value: vId,
			},
			Summary: utils.SafelyGetValue(v.Summary),
		}

		if strings.HasPrefix(vId, "CVE-") {
			vulnerability.Id.Type = vulnerabilityv1.VulnerabilityIdentifierType_VULNERABILITY_IDENTIFIER_TYPE_CVE
		} else if strings.HasPrefix(vId, "OSV-") {
			vulnerability.Id.Type = vulnerabilityv1.VulnerabilityIdentifierType_VULNERABILITY_IDENTIFIER_TYPE_OSV
		}

		req.PackageVersionInsight.Vulnerabilities = append(req.PackageVersionInsight.Vulnerabilities, &vulnerability)
	}

	// Add project information
	project := utils.SafelyGetValue(insights.Projects)
	for _, p := range project {
		stars := int64(utils.SafelyGetValue(p.Stars))
		forks := int64(utils.SafelyGetValue(p.Forks))
		issues := int64(utils.SafelyGetValue(p.Issues))

		vt := packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_UNSPECIFIED
		switch utils.SafelyGetValue(p.Type) {
		case "GITHUB":
			vt = packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB
		case "GITLAB":
			vt = packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITLAB
		}

		req.PackageVersionInsight.ProjectInsights = append(req.PackageVersionInsight.ProjectInsights, &packagev1.ProjectInsight{
			Project: &packagev1.Project{
				Type: vt,
				Name: utils.SafelyGetValue(p.Name),
				Url:  utils.SafelyGetValue(p.Link),
			},

			Stars: &stars,
			Forks: &forks,
			Issues: &packagev1.ProjectInsight_IssueStat{
				Total: issues,
			},
		})
	}

	licenses := utils.SafelyGetValue(insights.Licenses)
	for _, license := range licenses {
		req.PackageVersionInsight.Licenses.Licenses = append(req.PackageVersionInsight.Licenses.Licenses, &packagev1.LicenseMeta{
			LicenseId: string(license),
			Name:      string(license),
		})
	}

	// OpenSSF
	// We can't use vet's collected scorecard because its data model is wrong. There is
	// not a single scorecard per package. Rather there is a scorecard per project. Since
	// a package may be related to multiple projects, we will have multiple related scorecards.

	_, err = session.toolServiceClient.PublishPackageInsight(context.Background(), &req)
	if err != nil {
		return fmt.Errorf("failed to publish package insight: %w", err)
	}

	return nil
}
