package reporter

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/controltower/v1/controltowerv1grpc"
	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/utils"
	"google.golang.org/grpc"

	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/readers"
)

const syncReporterDefaultWorkerCount = 10

// SyncReporterEnvResolver defines the contract for implementing environment resolver for the sync reporter.
// Here we decouple the actual implementation of the resolver to the
// client that uses the reporter plugin. The resolver is used to provide
// environment awareness to the reporter. For example, when running in GitHub
// or on a Git repository, the resolver can provide the project source, project
// and other information that is required to create a tool session.
type SyncReporterEnvResolver interface {
	// The resolved source of the runtime environment (e.g. GitHub)
	GetProjectSource() controltowerv1pb.Project_Source

	// The resolved URL of the runtime environment (e.g. GitHub repository URL)
	GetProjectURL() string

	// The trigger of the runtime environment (e.g. CI/CD pipeline)
	Trigger() controltowerv1.ToolTrigger

	// The Git reference of the runtime environment (e.g. branch, tag, commit)
	GitRef() string

	// The Git SHA of the runtime environment (e.g. commit hash)
	GitSha() string
}

type defaultSyncReporterEnvResolver struct{}

// GetProjectSource returns the source of the runtime environment (e.g. GitHub)
func (r *defaultSyncReporterEnvResolver) GetProjectSource() controltowerv1pb.Project_Source {
	return controltowerv1pb.Project_SOURCE_UNSPECIFIED
}

// GetProjectURL returns the URL of the runtime environment (e.g. GitHub repository URL)
func (r *defaultSyncReporterEnvResolver) GetProjectURL() string {
	return ""
}

// GitRef returns the Git reference of the runtime environment (e.g. branch, tag, commit)
func (r *defaultSyncReporterEnvResolver) GitRef() string {
	return ""
}

// GitSha returns the Git SHA of the runtime environment (e.g. commit hash)
func (r *defaultSyncReporterEnvResolver) GitSha() string {
	return ""
}

// Trigger returns the trigger of the runtime environment (e.g. CI/CD pipeline)
func (r *defaultSyncReporterEnvResolver) Trigger() controltowerv1.ToolTrigger {
	return controltowerv1.ToolTrigger_TOOL_TRIGGER_MANUAL
}

// DefaultSyncReporterEnvResolver returns the default environment resolver for the sync reporter.
// This is used when no environment resolver is provided.
func DefaultSyncReporterEnvResolver() SyncReporterEnvResolver {
	return &defaultSyncReporterEnvResolver{}
}

// SyncReporterConfig defines the configuration for the sync reporter.
type SyncReporterConfig struct {
	// gRPC connection for ControlTower
	ClientConnection *grpc.ClientConn

	// Enable multi-project syncing
	// In this case, a new project is created per package manifest
	EnableMultiProjectSync bool

	// Required when scanning a single project
	ProjectName    string
	ProjectVersion string

	// Performance
	WorkerCount int

	// Tool details
	Tool ToolMetadata
}

type syncSession struct {
	sessionID         string
	toolServiceClient controltowerv1grpc.ToolServiceClient
}

type syncSessionPool struct {
	mu           sync.RWMutex
	syncSessions map[string]syncSession
}

// Only use this session
func (s *syncSessionPool) addPrimarySession(sessionID string, client controltowerv1grpc.ToolServiceClient) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.syncSessions["*"] = syncSession{
		sessionID:         sessionID,
		toolServiceClient: client,
	}
}

func (s *syncSessionPool) hasKeyedSession(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.syncSessions[key]
	return ok
}

func (s *syncSessionPool) addKeyedSession(key, sessionID string, client controltowerv1grpc.ToolServiceClient) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.syncSessions[key] = syncSession{
		sessionID:         sessionID,
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
	config      *SyncReporterConfig
	workQueue   chan *workItem
	done        chan bool
	wg          sync.WaitGroup
	client      *grpc.ClientConn
	sessions    *syncSessionPool
	envResolver SyncReporterEnvResolver
	callbacks   SyncReporterCallbacks
}

// Verify syncReporter implements the Reporter interface
var _ Reporter = (*syncReporter)(nil)

func NewSyncReporterEnvironmentResolver() SyncReporterEnvResolver {
	// The `GITHUB_ACTIONS` environment variable is always set to true when GitHub Actions is running the workflow
	if _, exists := os.LookupEnv("GITHUB_ACTIONS"); exists {
		return GithubActionsSyncReporterResolver()
	}

	return DefaultSyncReporterEnvResolver()
}

// NewSyncReporter creates a new sync reporter.
func NewSyncReporter(config SyncReporterConfig, envResolver SyncReporterEnvResolver, callbacks SyncReporterCallbacks) (*syncReporter, error) {
	if config.ClientConnection == nil {
		return nil, fmt.Errorf("missing gRPC client connection")
	}

	if envResolver == nil {
		return nil, fmt.Errorf("missing environment resolver")
	}

	syncSessionPool := syncSessionPool{
		syncSessions: make(map[string]syncSession),
	}

	done := make(chan bool)
	self := &syncReporter{
		config:      &config,
		done:        done,
		workQueue:   make(chan *workItem, 1000),
		client:      config.ClientConnection,
		sessions:    &syncSessionPool,
		callbacks:   callbacks,
		envResolver: envResolver,
	}

	// A multi-project sync is required for cases like GitHub org where
	// we are scanning multiple repositories
	if !config.EnableMultiProjectSync {
		logger.Debugf("Report Sync: Creating tool session for project: %s, version: %s",
			config.ProjectName, config.ProjectVersion)

		// Refactor this into a common session creator function
		toolServiceClient := controltowerv1grpc.NewToolServiceClient(config.ClientConnection)
		toolSessionRes, err := toolServiceClient.CreateToolSession(context.Background(),
			self.createToolSessionRequestForProjectVersion(config.ProjectName, config.ProjectVersion))
		if err != nil {
			return nil, fmt.Errorf("failed to create tool session: %w", err)
		}

		logger.Debugf("Report Sync: Tool data upload session ID: %s",
			toolSessionRes.GetToolSession().GetToolSessionId())

		syncSessionPool.addPrimarySession(toolSessionRes.GetToolSession().GetToolSessionId(),
			toolServiceClient)
	}

	self.dispatchOnSyncStart()
	self.startWorkers()
	return self, nil
}

// Name returns the name of the sync reporter.
func (s *syncReporter) Name() string {
	return "Cloud Sync Reporter"
}

// AddManifest adds a manifest to the sync reporter.
func (s *syncReporter) AddManifest(manifest *models.PackageManifest) {
	manifestSessionKey := manifest.Path
	if s.config.EnableMultiProjectSync && !s.sessions.hasKeyedSession(manifestSessionKey) {
		projectName := manifest.GetSource().GetNamespace()
		projectVersion := "main"

		logger.Debugf("Report Sync: Creating tool session for project: %s, version: %s",
			projectName, projectVersion)

		toolServiceClient := controltowerv1grpc.NewToolServiceClient(s.client)
		toolSessionRes, err := toolServiceClient.CreateToolSession(context.Background(),
			s.createToolSessionRequestForProjectVersion(projectName, projectVersion))
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

// AddAnalyzerEvent adds an analyzer event to the sync reporter.
func (s *syncReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	s.queueEvent(event)
}

// AddPolicyEvent adds a policy event to the sync reporter.
func (s *syncReporter) AddPolicyEvent(event *policy.PolicyEvent) {
}

// Finish finishes the sync reporter.
func (s *syncReporter) Finish() error {
	s.wg.Wait()
	s.dispatchOnSyncFinish()
	close(s.done)

	return s.sessions.forEach(func(_ string, session *syncSession) error {
		logger.Debugf("Report Sync: Completing tool session: %s", session.sessionID)

		_, err := session.toolServiceClient.CompleteToolSession(context.Background(),
			&controltowerv1.CompleteToolSessionRequest{
				ToolSession: &controltowerv1.ToolSession{
					ToolSessionId: session.sessionID,
				},
				Status: controltowerv1.CompleteToolSessionRequest_STATUS_SUCCESS,
			})

		return err
	})
}

func (s *syncReporter) queueEvent(event *analyzer.AnalyzerEvent) {
	s.wg.Add(1)
	s.dispatchOnEventSync(event)
	s.workQueue <- &workItem{event: event}
}

func (s *syncReporter) queuePackage(pkg *models.Package) {
	s.wg.Add(1)
	s.dispatchOnPackageSync(pkg)
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
			ToolSessionId: session.sessionID,
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

	s.dispatchOnEventSyncDone(event)
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
			ToolSessionId: session.sessionID,
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
		vulnerabilityID := utils.SafelyGetValue(v.Id)
		vulnerability := vulnerabilityv1.Vulnerability{
			Id: &vulnerabilityv1.VulnerabilityIdentifier{
				Value: vulnerabilityID,
			},
			Summary: utils.SafelyGetValue(v.Summary),
		}

		if strings.HasPrefix(vulnerabilityID, "CVE-") {
			vulnerability.Id.Type = vulnerabilityv1.VulnerabilityIdentifierType_VULNERABILITY_IDENTIFIER_TYPE_CVE
		} else if strings.HasPrefix(vulnerabilityID, "OSV-") {
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

	// Add malware analysis information if available
	if mar := pkg.GetMalwareAnalysisResult(); mar != nil {
		req.MaliciousPackageInsight = &controltowerv1.PublishPackageInsightRequest_MaliciousPackageInsight{
			AnalysisId: mar.AnalysisId,
			IsMalware:  mar.IsMalware || mar.IsSuspicious,
			IsVerified: mar.VerificationRecord != nil,
		}

		// Add summary if available
		if mar.Report != nil && mar.Report.GetInference() != nil {
			req.MaliciousPackageInsight.Summary = mar.Report.GetInference().GetSummary()
		}

		logger.Debugf("Report Sync: Added malware analysis for package: %s/%s/%s (malware: %t, verified: %t)",
			pkg.GetControlTowerSpecEcosystem(), pkg.GetName(), pkg.GetVersion(),
			mar.IsMalware || mar.IsSuspicious, req.MaliciousPackageInsight.IsVerified)
	}

	// OpenSSF
	// We can't use vet's collected scorecard because its data model is wrong. There is
	// not a single scorecard per package. Rather there is a scorecard per project. Since
	// a package may be related to multiple projects, we will have multiple related scorecards.

	_, err = session.toolServiceClient.PublishPackageInsight(context.Background(), &req)
	if err != nil {
		return fmt.Errorf("failed to publish package insight: %w", err)
	}

	s.dispatchOnPackageSyncDone(pkg)
	return nil
}

func (s *syncReporter) createToolSessionRequestForProjectVersion(projectName, projectVersion string) *controltowerv1.CreateToolSessionRequest {
	source := packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_UNSPECIFIED
	trigger := s.envResolver.Trigger()
	originSource := s.envResolver.GetProjectSource()
	originURL := s.envResolver.GetProjectURL()
	gitRef := s.envResolver.GitRef()
	gitSha := s.envResolver.GitSha()

	req := &controltowerv1.CreateToolSessionRequest{
		ToolName:       s.config.Tool.Name,
		ToolVersion:    s.config.Tool.Version,
		ProjectName:    projectName,
		ProjectVersion: &projectVersion,
		ProjectSource:  &source,
	}

	if trigger != controltowerv1.ToolTrigger_TOOL_TRIGGER_UNSPECIFIED {
		req.Trigger = &trigger
	}

	if originSource != controltowerv1pb.Project_SOURCE_UNSPECIFIED {
		req.OriginProjectSource = &originSource
	}

	if originURL != "" {
		req.OriginProjectUrl = &originURL
	}

	if gitRef != "" {
		req.GitRef = &gitRef
	}

	if gitSha != "" {
		req.GitSha = &gitSha
	}

	return req
}
