package reporter

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync"

	api_errors "github.com/safedep/dry/errors"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/syncv1"
	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/readers"
)

const (
	syncReporterDefaultWorkerCount = 10
	syncReporterMaxRetries         = 3
	syncReporterToolName           = "vet"
)

type SyncReporterConfig struct {
	// Required
	ProjectName  string
	StreamName   string
	TriggerEvent string

	// Optional or auto-discovered from environment
	ProjectSource string
	GitRef        string
	GitRefName    string
	GitRefType    string
	GitSha        string

	// Performance
	WorkerCount int

	// Internal config
	toolName    string
	toolVersion string
	toolType    string
}

type syncIssueWrapper struct {
	retries int
	issue   any
}

type syncReporter struct {
	client       *syncv1.ClientWithResponses
	config       *SyncReporterConfig
	issueChannel chan *syncIssueWrapper
	done         chan bool
	wg           sync.WaitGroup
	jobId        string
}

func NewSyncReporter(config SyncReporterConfig) (Reporter, error) {
	apiKeyApplier := func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", auth.ApiKey())
		return nil
	}

	// TODO: Use hysterix as the API client with retries, backoff
	// connection pooling etc.

	client, err := syncv1.NewClientWithResponses(auth.DefaultSyncApiUrl(),
		syncv1.WithRequestEditorFn(apiKeyApplier))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize client for sync reporter: %w", err)
	}

	config.TriggerEvent = string(syncv1.CreateJobRequestTriggerEventManual)
	config.ProjectSource = string(syncv1.CreateJobRequestProjectSourceOther)
	config.toolType = string(syncv1.CreateJobRequestToolTypeOssVet)
	config.toolName = syncReporterToolName
	config.toolVersion = "FIXME"

	// TODO: Use an interface to auto-discover environmental details
	// if not provided and update config

	err = validateSyncReporterConfig(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to validate sync reporter config : %w", err)
	}

	jobId, err := createJobForSyncReportSession(client, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to create job for sync reporter: %w", err)
	}

	done := make(chan bool)
	issuesChan := make(chan *syncIssueWrapper, 100000)

	self := &syncReporter{
		config:       &config,
		client:       client,
		issueChannel: issuesChan,
		jobId:        jobId,
		done:         done,
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

		s.queuePackageDependencyIssue(manifest, pkg)
		s.queuePackageMetadataIssue(manifest, pkg)
		s.queuePackageLicenseIssue(manifest, pkg)
		s.queuePackageVulnerabilityIssue(manifest, pkg)
		s.queuePackageScorecardIssue(manifest, pkg)

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

func (s *syncReporter) queueIssueForSync(issue *syncIssueWrapper) {
	s.wg.Add(1)
	s.issueChannel <- issue
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
		case issue := <-s.issueChannel:
			err := s.syncReportIssue(issue)
			if err != nil {
				logger.Errorf("failed to sync issue: %v", err)
			}
		case <-s.done:
			return
		}
	}
}

func (s *syncReporter) syncReportIssue(iw *syncIssueWrapper) error {
	defer s.wg.Done()

	res, err := s.client.CreateJobIssueWithResponse(context.Background(), s.jobId, iw.issue)
	if err != nil {
		return err
	}

	defer res.HTTPResponse.Body.Close()

	if res.HTTPResponse.StatusCode != http.StatusCreated {
		apiErr, _ := api_errors.UnmarshalApiError(res.Body)
		if apiErr.Retriable() && (iw.retries < syncReporterMaxRetries) {
			iw.retries++
			s.queueIssueForSync(iw)
			return nil
		}

		return fmt.Errorf("invalid response code %d from Issue API : %w",
			res.HTTPResponse.StatusCode, err)
	}

	response := utils.SafelyGetValue(res.JSON201)
	logger.Debugf("Synced issued with ID: %s", response.Id)

	return nil
}

func (s *syncReporter) buildPackageIssue(issueType syncv1.IssueIssueType,
	manifest *models.PackageManifest, pkg *models.Package) syncv1.PackageIssue {
	ecosystem := syncv1.PackageIssueManifestEcosystem(manifest.Ecosystem)
	return syncv1.PackageIssue{
		Issue: syncv1.Issue{
			IssueType: issueType,
		},
		ManifestEcosystem: &ecosystem,
		ManifestPath:      &manifest.Path,
		PackageName:       &pkg.Name,
		PackageVersion:    &pkg.Version,
	}
}

func (s *syncReporter) queuePackageDependencyIssue(manifest *models.PackageManifest, pkg *models.Package) {
	issue := syncv1.IssuePackageDependency{
		PackageIssue: s.buildPackageIssue(syncv1.IssueIssueTypePackageDependency,
			manifest, pkg),
	}

	if pkg.Parent != nil {
		issue.ParentPackageName = &pkg.Parent.Name
		issue.ParentPackageVersion = &pkg.Parent.Version
	}

	iw := syncIssueWrapper{issue: issue}
	s.queueIssueForSync(&iw)
}

func (s *syncReporter) queuePackageMetadataIssue(manifest *models.PackageManifest, pkg *models.Package) {
	insights := utils.SafelyGetValue(pkg.Insights)
	projects := utils.SafelyGetValue(insights.Projects)

	for _, project := range projects {
		issue := syncv1.IssuePackageSource{
			PackageIssue: s.buildPackageIssue(syncv1.IssueIssueTypePackageSourceInfo,
				manifest, pkg),
		}

		sourceType := utils.SafelyGetValue(project.Type)
		issueSourceType := syncv1.IssuePackageSourceSourceTypeOther

		switch sourceType {
		case "GITHUB":
			issueSourceType = syncv1.IssuePackageSourceSourceTypeGithub
		case "BITBUCKET":
			issueSourceType = syncv1.IssuePackageSourceSourceTypeBitbucket
		case "GITLAB":
			issueSourceType = syncv1.IssuePackageSourceSourceTypeGitlab
		}

		issue.SourceType = &issueSourceType
		issue.SourceUrl = project.Link
		issue.SourceDisplayName = project.DisplayName
		issue.SourceForks = project.Forks
		issue.SourceStars = project.Stars

		s.queueIssueForSync(&syncIssueWrapper{issue: issue})
	}
}

func (s *syncReporter) queuePackageLicenseIssue(manifest *models.PackageManifest, pkg *models.Package) {
	insights := utils.SafelyGetValue(pkg.Insights)
	licenses := utils.SafelyGetValue(insights.Licenses)

	for _, license := range licenses {
		licenseId := syncv1.IssuePackageLicenseLicenseId(license)
		issue := syncv1.IssuePackageLicense{
			PackageIssue: s.buildPackageIssue(syncv1.IssueIssueTypePackageLicense,
				manifest, pkg),
			LicenseId: &licenseId,
		}

		s.queueIssueForSync(&syncIssueWrapper{issue: issue})
	}
}

func (s *syncReporter) queuePackageVulnerabilityIssue(manifest *models.PackageManifest, pkg *models.Package) {
	insights := utils.SafelyGetValue(pkg.Insights)
	vulnerabilities := utils.SafelyGetValue(insights.Vulnerabilities)

	for _, vuln := range vulnerabilities {
		issue := syncv1.IssuePackageVulnerability{
			PackageIssue: s.buildPackageIssue(syncv1.IssueIssueTypePackageVulnerability,
				manifest, pkg),
		}

		severities := []struct {
			Risk  *syncv1.IssuePackageCommonVulnerabilitySeveritiesRisk `json:"risk,omitempty"`
			Score *string                                               `json:"score,omitempty"`
			Type  *syncv1.IssuePackageCommonVulnerabilitySeveritiesType `json:"type,omitempty"`
		}{}

		issue.Vulnerability = &syncv1.IssuePackageCommonVulnerability{
			Id:      vuln.Id,
			Summary: vuln.Summary,
			Aliases: vuln.Aliases,
			Related: vuln.Related,
		}

		for _, severity := range utils.SafelyGetValue(vuln.Severities) {
			sRisk := syncv1.IssuePackageCommonVulnerabilitySeveritiesRisk(utils.SafelyGetValue(severity.Risk))
			sType := syncv1.IssuePackageCommonVulnerabilitySeveritiesType(utils.SafelyGetValue(severity.Type))

			severities = append(severities, struct {
				Risk  *syncv1.IssuePackageCommonVulnerabilitySeveritiesRisk `json:"risk,omitempty"`
				Score *string                                               `json:"score,omitempty"`
				Type  *syncv1.IssuePackageCommonVulnerabilitySeveritiesType `json:"type,omitempty"`
			}{
				Score: severity.Score,
				Risk:  &sRisk,
				Type:  &sType,
			})
		}

		issue.Vulnerability.Severities = &severities
		s.queueIssueForSync(&syncIssueWrapper{issue: issue})
	}
}

func (s *syncReporter) queuePackageScorecardIssue(manifest *models.PackageManifest, pkg *models.Package) {
	insights := utils.SafelyGetValue(pkg.Insights)

	// Basic sanity test to fail fast if Scorecard is unavailable
	if (insights.Scorecard == nil) || (insights.Scorecard.Content == nil) {
		return
	}

	scorecard := utils.SafelyGetValue(insights.Scorecard)
	scorecardContent := utils.SafelyGetValue(scorecard.Content)
	scorecardRepo := utils.SafelyGetValue(scorecardContent.Repository)
	scorecardChecks := utils.SafelyGetValue(scorecardContent.Checks)

	date := utils.SafelyGetValue(scorecardContent.Date).Format("2006-01-02")
	repo := struct {
		Commit *string `json:"commit,omitempty"`
		Name   *string `json:"name,omitempty"`
	}{
		Commit: scorecardRepo.Commit,
		Name:   scorecardRepo.Name,
	}

	checks := []struct {
		Details       *[]string `json:"details,omitempty"`
		Documentation *struct {
			Short *string `json:"short,omitempty"`
			Url   *string `json:"url,omitempty"`
		} `json:"documentation,omitempty"`
		Name   *string `json:"name,omitempty"`
		Reason *string `json:"reason,omitempty"`
		Score  *int    `json:"score"`
	}{}

	for _, check := range scorecardChecks {
		// We have to do this stupid type conversion because Scorecard check score seems
		// be to int / float32 in different specs. We are good with downsizing width because
		// scorecard score is max 10
		checkScore := utils.SafelyGetValue(check.Score)
		checkScoreInt := int(math.Round(float64(checkScore)))

		checks = append(checks, struct {
			Details       *[]string `json:"details,omitempty"`
			Documentation *struct {
				Short *string `json:"short,omitempty"`
				Url   *string `json:"url,omitempty"`
			} `json:"documentation,omitempty"`
			Name   *string `json:"name,omitempty"`
			Reason *string `json:"reason,omitempty"`
			Score  *int    `json:"score"`
		}{
			Details: check.Details,
			Name:    (*string)(check.Name),
			Reason:  check.Reason,
			Score:   &checkScoreInt,
		})
	}

	issue := &syncv1.IssuePackageScorecard{
		PackageIssue: s.buildPackageIssue(syncv1.IssueIssueTypePackageOpenssfScorecard,
			manifest, pkg),
		Date:   &date,
		Score:  scorecardContent.Score,
		Repo:   &repo,
		Checks: &checks,
	}

	s.queueIssueForSync(&syncIssueWrapper{issue: issue})
}

func validateSyncReporterConfig(config *SyncReporterConfig) error {
	if utils.IsEmptyString(config.ProjectName) {
		return errors.New("project name not in config")
	}

	if utils.IsEmptyString(config.StreamName) {
		return errors.New("stream name not in config")
	}

	if utils.IsEmptyString(config.TriggerEvent) {
		return errors.New("trigger event not in config")
	}

	return nil
}

func createJobForSyncReportSession(client *syncv1.ClientWithResponses,
	config *SyncReporterConfig) (string, error) {

	jobConfig := syncv1.CreateSyncJobJSONRequestBody{
		ProjectName:   config.ProjectName,
		ProjectSource: syncv1.CreateJobRequestProjectSource(config.ProjectSource),
		StreamName:    config.StreamName,
		TriggerEvent:  syncv1.CreateJobRequestTriggerEvent(config.TriggerEvent),
		ToolType:      syncv1.CreateJobRequestToolType(config.toolType),
		ToolName:      config.toolName,
		ToolVersion:   config.toolVersion,
		GitRefType:    (*syncv1.CreateJobRequestGitRefType)(&config.GitRefType),
		GitRef:        &config.GitRef,
		GitRefName:    &config.GitRefName,
		GitSha:        &config.GitSha,
	}

	job, err := client.CreateSyncJobWithResponse(context.Background(), jobConfig)
	if err != nil {
		return "", err
	}

	defer job.HTTPResponse.Body.Close()

	if job.HTTPResponse.StatusCode != http.StatusCreated {
		err, _ = api_errors.UnmarshalApiError(job.Body)
		return "", fmt.Errorf("invalid response code %d from Job API : %w",
			job.HTTPResponse.StatusCode, err)
	}

	res := utils.SafelyGetValue(job.JSON201)
	return utils.SafelyGetValue(res.Id), nil
}
