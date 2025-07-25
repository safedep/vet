package main

import (
	"fmt"
	"os"
	"time"

	"github.com/google/go-github/v70/github"
	"github.com/safedep/dry/adapters"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/internal/analytics"
	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/command"
	"github.com/safedep/vet/internal/connect"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/code"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/registry"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/parser"
	"github.com/safedep/vet/pkg/readers"
	"github.com/safedep/vet/pkg/reporter"
	"github.com/safedep/vet/pkg/scanner"
	"github.com/safedep/vet/pkg/storage"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var (
	manifests                        []string
	manifestType                     string
	lockfiles                        []string
	lockfileAs                       string
	enrich                           bool
	enrichUsingInsightsV2            bool
	enrichMalware                    bool
	enrichMalwareQuery               bool
	baseDirectory                    string
	purlSpec                         string
	vsxReader                        bool
	vsxDirectories                   []string
	githubRepoUrls                   []string
	githubOrgUrl                     string
	githubOrgMaxRepositories         int
	githubOrgExcludedRepos           []string
	githubSkipDependencyGraphAPI     bool
	scanExclude                      []string
	transitiveAnalysis               bool
	transitiveDepth                  int
	dependencyUsageEvidence          bool
	codeAnalysisDBPath               string
	concurrency                      int
	dumpJsonManifestDir              string
	celFilterExpression              string
	celFilterSuiteFile               string
	celFilterFailOnMatch             bool
	markdownReportPath               string
	markdownSummaryReportPath        string
	jsonReportPath                   string
	consoleReport                    bool
	summaryReport                    bool
	summaryReportMaxAdvice           int
	summaryReportGroupByDirectDeps   bool
	summaryReportUsedOnly            bool
	csvReportPath                    string
	reportDefectDojo                 bool
	defectDojoHostUrl                string
	defectDojoProductID              int
	sarifReportPath                  string
	sarifIncludeVulns                bool
	sarifIncludeMalware              bool
	cyclonedxReportPath              string
	cyclonedxReportApplicationName   string
	silentScan                       bool
	disableAuthVerifyBeforeScan      bool
	syncReport                       bool
	syncReportProject                string
	syncEnableMultiProject           bool
	graphReportDirectory             string
	syncReportStream                 string
	listExperimentalParsers          bool
	failFast                         bool
	trustedRegistryUrls              []string
	scannerExperimental              bool
	malwareAnalyzerTrustToolResult   bool
	malwareAnalysisTimeout           time.Duration
	malwareAnalysisMinimumConfidence string
	gitlabReportPath                 string
	sqlite3ReportPath                string
	sqlite3ReportOverwrite           bool
	sqlite3ReportAppend              bool
	scanImageTarget                  string
	scanImageNoRemote                bool
)

func newScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan and analyse package manifests",
		RunE: func(cmd *cobra.Command, args []string) error {
			startScan()
			return nil
		},
	}

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	cmd.Flags().BoolVarP(&silentScan, "silent", "s", false,
		"Silent scan to prevent rendering UI")
	cmd.Flags().BoolVarP(&failFast, "fail-fast", "", false,
		"Fail fast when an issue is identified")
	cmd.Flags().BoolVarP(&enrich, "enrich", "", true,
		"Enrich package metadata (almost always required) using Insights API")
	cmd.Flags().BoolVarP(&enrichUsingInsightsV2, "insights-v2", "", false,
		"Enrich package metadata using Insights V2 API")
	cmd.Flags().BoolVarP(&enrichMalware, "malware", "", false,
		"Enrich package metadata with active malware analysis results")
	cmd.Flags().BoolVarP(&enrichMalwareQuery, "malware-query", "", true,
		"Enrich package metadata with known malicious packages data")
	cmd.Flags().StringVarP(&baseDirectory, "directory", "D", wd,
		"The directory to scan for package manifests")
	cmd.Flags().StringArrayVarP(&scanExclude, "exclude", "", []string{},
		"Name patterns to ignore while scanning")
	cmd.Flags().StringArrayVarP(&lockfiles, "lockfiles", "L", []string{},
		"List of lockfiles to scan")
	cmd.Flags().StringArrayVarP(&manifests, "manifests", "M", []string{},
		"List of package manifest or archive to scan (example: jar:/tmp/foo.jar)")
	cmd.Flags().StringVarP(&purlSpec, "purl", "", "",
		"PURL to scan")
	cmd.Flags().BoolVarP(&vsxReader, "vsx", "", false,
		"Read VSCode extensions from VSCode extensions directory")
	cmd.Flags().StringArrayVarP(&vsxDirectories, "vsx-dir", "", []string{},
		"VSCode extensions directory to scan (default: auto-detect)")
	cmd.Flags().StringArrayVarP(&githubRepoUrls, "github", "", []string{},
		"Github repository URL (Example: https://github.com/{org}/{repo})")
	cmd.Flags().StringVarP(&githubOrgUrl, "github-org", "", "",
		"Github organization URL (Example: https://github.com/safedep)")
	cmd.Flags().IntVarP(&githubOrgMaxRepositories, "github-org-max-repo", "", 1000,
		"Maximum number of repositories to process for the Github Org")
	cmd.Flags().StringArrayVarP(&githubOrgExcludedRepos, "github-org-exclude-repos", "", []string{},
		"Comma-separated list of GitHub repos to exclude during org scan (format: org/repo1,org/repo2)")
	cmd.Flags().BoolVarP(&githubSkipDependencyGraphAPI, "skip-github-dependency-graph-api", "", false,
		"Do not use GitHub Dependency Graph API to fetch dependencies")
	cmd.Flags().StringVarP(&lockfileAs, "lockfile-as", "", "",
		"Parser to use for the lockfile (vet scan parsers to list)")
	cmd.Flags().StringVarP(&manifestType, "type", "", "",
		"Parser to use for the artifact (vet scan parsers --experimental to list)")
	cmd.Flags().BoolVarP(&transitiveAnalysis, "transitive", "", false,
		"Analyze transitive dependencies")
	cmd.Flags().IntVarP(&transitiveDepth, "transitive-depth", "", 2,
		"Analyze transitive dependencies till depth")
	cmd.Flags().StringVarP(&codeAnalysisDBPath, "code", "", "", "Path to code analysis database generated by 'vet code scan'")
	cmd.Flags().BoolVarP(&dependencyUsageEvidence, "code-dependency-usage-evidence", "", true, "Enable dependency usage evidence during scan")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "C", 5,
		"Number of concurrent analysis to run")
	cmd.Flags().StringVarP(&dumpJsonManifestDir, "json-dump-dir", "", "",
		"Dump enriched package manifests as JSON files to dir")
	cmd.Flags().StringVarP(&celFilterExpression, "filter", "", "",
		"Filter and print packages using CEL")
	cmd.Flags().StringVarP(&celFilterSuiteFile, "filter-suite", "", "",
		"Filter packages using CEL Filter Suite from file")
	cmd.Flags().BoolVarP(&celFilterFailOnMatch, "filter-fail", "", false,
		"Fail the scan if the filter match any package (security gate)")
	cmd.Flags().BoolVarP(&disableAuthVerifyBeforeScan, "no-verify-auth", "", false,
		"Do not verify auth token before starting scan")
	cmd.Flags().StringVarP(&markdownReportPath, "report-markdown", "", "",
		"Generate consolidated markdown report to file")
	cmd.Flags().StringVarP(&markdownSummaryReportPath, "report-markdown-summary", "", "",
		"Generate consolidate summary in markdown")
	cmd.Flags().BoolVarP(&consoleReport, "report-console", "", false,
		"Print a report to the console")
	cmd.Flags().BoolVarP(&summaryReport, "report-summary", "", true,
		"Print a summary report with actionable advice")
	cmd.Flags().IntVarP(&summaryReportMaxAdvice, "report-summary-max-advice", "", 5,
		"Maximum number of package risk advice to show")
	cmd.Flags().BoolVarP(&summaryReportGroupByDirectDeps, "report-summary-group-by-direct-deps", "", false,
		"Group summary report by direct dependencies")
	cmd.Flags().BoolVarP(&summaryReportUsedOnly, "report-summary-used-only", "", false,
		"Show only packages that are used in code (requires code analysis)")
	cmd.Flags().StringVarP(&csvReportPath, "report-csv", "", "",
		"Generate CSV report of filtered packages")
	cmd.Flags().BoolVarP(&reportDefectDojo, "report-defect-dojo", "", false, "Report to DefectDojo")
	cmd.Flags().StringVarP(&defectDojoHostUrl, "defect-dojo-host-url", "", "",
		"DefectDojo Host URL eg. http://localhost:8080")
	cmd.Flags().IntVarP(&defectDojoProductID, "defect-dojo-product-id", "", -1, "DefectDojo Product ID")
	cmd.Flags().StringVarP(&jsonReportPath, "report-json", "", "",
		"Generate consolidated JSON report to file (EXPERIMENTAL schema)")
	cmd.Flags().StringVarP(&sarifReportPath, "report-sarif", "", "",
		"Generate SARIF report to file (*.sarif or *.sarif.json)")
	cmd.Flags().BoolVarP(&sarifIncludeVulns, "report-sarif-vulns", "", true, "Include vulnerabilities in SARIF report (Enabled by default)")
	cmd.Flags().BoolVarP(&sarifIncludeMalware, "report-sarif-malware", "", true, "Include malware in SARIF report (Enabled by default)")
	cmd.Flags().StringVarP(&cyclonedxReportPath, "report-cdx", "", "",
		"Generate CycloneDX report to file")
	cmd.Flags().StringVarP(&cyclonedxReportApplicationName, "report-cdx-app-name", "", "",
		"Application name used as root application component in CycloneDX BOM")
	cmd.Flags().StringVarP(&graphReportDirectory, "report-graph", "", "",
		"Generate dependency graph (if available) as dot files to directory")
	cmd.Flags().BoolVarP(&syncReport, "report-sync", "", false,
		"Enable syncing report data to cloud")
	cmd.Flags().StringVarP(&syncReportProject, "report-sync-project", "", "",
		"Project name to use in cloud")
	cmd.Flags().BoolVarP(&syncEnableMultiProject, "report-sync-multi-project", "", false,
		"Lazily create cloud sessions for multiple projects (per manifest)")
	cmd.Flags().StringVarP(&syncReportStream, "report-sync-project-version", "", "",
		"Project stream name (e.g. branch) to use in cloud")
	cmd.Flags().StringArrayVarP(&trustedRegistryUrls, "trusted-registry", "", []string{},
		"Trusted registry URLs to use for package manifest verification")
	cmd.Flags().BoolVarP(&scannerExperimental, "experimental", "", false,
		"Enable experimental features in scanner")
	cmd.Flags().BoolVarP(&malwareAnalyzerTrustToolResult, "malware-trust-tool-result", "", false,
		"Trust malicious package analysis tool result without verification record")
	cmd.Flags().DurationVarP(&malwareAnalysisTimeout, "malware-analysis-timeout", "", 5*time.Minute,
		"Timeout for malicious package analysis")
	cmd.Flags().StringVarP(&gitlabReportPath, "report-gitlab", "", "",
		"Generate GitLab dependency scanning report to file")
	cmd.Flags().StringVarP(&sqlite3ReportPath, "report-sqlite3", "", "",
		"Generate SQLite3 database report to file")
	cmd.Flags().BoolVarP(&sqlite3ReportOverwrite, "report-sqlite3-overwrite", "", false,
		"Overwrite existing SQLite3 database report")
	cmd.Flags().BoolVarP(&sqlite3ReportAppend, "report-sqlite3-append", "", false,
		"Append to existing SQLite3 database report")
	cmd.Flags().StringVarP(&malwareAnalysisMinimumConfidence, "malware-analysis-min-confidence", "", "HIGH",
		"Minimum confidence level for malicious package analysis result to fail fast")
	cmd.Flags().StringVarP(&scanImageTarget, "image", "", "",
		"Image reference to run container image scanning (eg. node:latest)")
	cmd.Flags().BoolVarP(&scanImageNoRemote, "image-no-remote", "", false,
		"Disable container image pulling when not found locally")

	// Add validations that should trigger a fail fast condition
	cmd.PreRun = func(cmd *cobra.Command, args []string) {
		err := func() error {
			if syncReport && version == "" {
				return fmt.Errorf("version is required for sync report, install vet using supported method: " +
					"https://docs.safedep.io/quickstart/")
			}

			if summaryReportUsedOnly && codeAnalysisDBPath == "" {
				return fmt.Errorf("summary report with used only packages requires code analysis database: " +
					"Enable with --code")
			}

			if reportDefectDojo && (defectDojoProductID == -1 || utils.IsEmptyString(defectDojoHostUrl)) {
				return fmt.Errorf("defect dojo Host URL & product ID are required for defect dojo report")
			}

			return nil
		}()

		command.FailOnError("pre-scan", err)
	}

	cmd.AddCommand(listParsersCommand())
	return cmd
}

func listParsersCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parsers",
		Short: "List available lockfile parsers",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Available Lockfile Parsers\n")
			fmt.Printf("==========================\n\n")

			for idx, p := range parser.List(listExperimentalParsers) {
				fmt.Printf("[%d] %s\n", idx, p)
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&listExperimentalParsers, "experimental", "", false,
		"Include experimental parsers in the list")

	return cmd
}

func startScan() {
	analytics.TrackCommandScan()

	if !disableAuthVerifyBeforeScan {
		err := auth.Verify()
		// We will fallback to community mode by default to provide
		// a seamless user experience
		if err != nil {
			auth.SetRuntimeCommunityMode()
		}
	}

	if auth.CommunityMode() {
		ui.PrintMsg("Running in Community Mode")
	} else {
		ui.PrintMsg("Running in Cloud (authenticated) Mode")
	}

	command.FailOnError("scan", internalStartScan())
}

func internalStartScan() error {
	toolMetadata := reporter.ToolMetadata{
		Name:                 vetName,
		Version:              version,
		Purl:                 vetPurl,
		InformationURI:       vetInformationURI,
		VendorName:           vetVendorName,
		VendorInformationURI: vetVendorInformationURI,
	}

	readerList := []readers.PackageManifestReader{}
	var reader readers.PackageManifestReader
	var err error

	githubClientBuilder := func() *github.Client {
		githubClient, err := connect.GetGithubClient()
		if err != nil {
			logger.Fatalf("Failed to build Github client: %v", err)
		}

		return githubClient
	}

	// manifestType will supersede lockfileAs and eventually deprecate it
	// But for now, manifestType is backward compatible with lockfileAs
	if manifestType != "" {
		lockfileAs = manifestType
	} else {
		manifestType = lockfileAs
	}

	// This is our standardized GitHub client.
	// We need to unify the GitHub client interfaces across different parts of vet
	// Current they depend on different versions of GitHub client
	githubClient, err := adapters.NewGithubClient(adapters.DefaultGitHubClientConfig())
	if err != nil {
		return err
	}

	versionResolver, err := registry.NewPackageVersionResolver(githubClient)
	if err != nil {
		return err
	}

	// We can easily support both directory and lockfile reader. But current UX
	// contract is to support one of them at a time. Lets not break the contract
	// for now and figure out UX improvement later
	if len(lockfiles) > 0 {
		analytics.TrackCommandScanPackageManifestScan()

		// nolint:ineffassign,staticcheck
		reader, err = readers.NewLockfileReader(readers.LockfileReaderConfig{
			Lockfiles:  lockfiles,
			LockfileAs: manifestType,
			Exclusions: scanExclude,
		})
	} else if len(manifests) > 0 {
		analytics.TrackCommandScanPackageManifestScan()

		// We will make manifestType backward compatible with lockfileAs
		if manifestType == "" {
			manifestType = lockfileAs
		}

		// nolint:ineffassign,staticcheck
		reader, err = readers.NewLockfileReader(readers.LockfileReaderConfig{
			Lockfiles:  manifests,
			LockfileAs: manifestType,
			Exclusions: scanExclude,
		})
	} else if len(githubRepoUrls) > 0 {
		analytics.TrackCommandScanGitHubScan()

		githubClient := githubClientBuilder()

		// nolint:ineffassign,staticcheck
		reader, err = readers.NewGithubReader(githubClient, readers.GitHubReaderConfig{
			Urls:                         githubRepoUrls,
			LockfileAs:                   lockfileAs,
			SkipGitHubDependencyGraphAPI: githubSkipDependencyGraphAPI,
		})
	} else if !utils.IsEmptyString(githubOrgUrl) {
		analytics.TrackCommandScanGitHubOrgScan()

		githubClient := githubClientBuilder()

		// nolint:ineffassign,staticcheck
		reader, err = readers.NewGithubOrgReader(githubClient, &readers.GithubOrgReaderConfig{
			OrganizationURL:        githubOrgUrl,
			IncludeArchived:        false,
			MaxRepositories:        githubOrgMaxRepositories,
			SkipDependencyGraphAPI: githubSkipDependencyGraphAPI,
			ExcludeRepos:           githubOrgExcludedRepos,
		})
	} else if len(purlSpec) > 0 {
		analytics.TrackCommandScanPurlScan()

		// nolint:ineffassign,staticcheck
		reader, err = readers.NewPurlReader(purlSpec, readers.PurlReaderConfig{AutoResolveMissingVersions: true}, versionResolver)
	} else if vsxReader {
		if len(vsxDirectories) == 0 {
			analytics.TrackCommandScanVSCodeExtScan()

			// nolint:ineffassign,staticcheck
			reader, err = readers.NewVSIXExtReaderFromDefaultDistributions()
		} else {
			analytics.TrackCommandScanVSCodeExtScan()

			// nolint:ineffassign,staticcheck
			reader, err = readers.NewVSIXExtReader(vsxDirectories)
		}
	} else if len(scanImageTarget) != 0 {
		analytics.TrackCommandImageScan()

		readerConfig := readers.DefaultContainerImageReaderConfig()

		if scanImageNoRemote {
			readerConfig.RemoteImageFetch = false
		}

		reader, err = readers.NewContainerImageReader(scanImageTarget, readerConfig)
	} else {
		analytics.TrackCommandScanDirectoryScan()

		// nolint:ineffassign,staticcheck
		reader, err = readers.NewDirectoryReader(readers.DirectoryReaderConfig{
			Path:                 baseDirectory,
			Exclusions:           scanExclude,
			ManifestTypeOverride: manifestType,
		})
	}

	if err != nil {
		return err
	}

	readerList = append(readerList, reader)

	// We will always use this analyzer
	lfpAnalyzer, err := analyzer.NewLockfilePoisoningAnalyzer(analyzer.LockfilePoisoningAnalyzerConfig{
		FailFast:            failFast,
		TrustedRegistryUrls: trustedRegistryUrls,
	})
	if err != nil {
		return err
	}

	analyzers := []analyzer.Analyzer{lfpAnalyzer}
	if !utils.IsEmptyString(dumpJsonManifestDir) {
		task, err := analyzer.NewJsonDumperAnalyzer(dumpJsonManifestDir)
		if err != nil {
			return err
		}

		analyzers = append(analyzers, task)
	}

	if !utils.IsEmptyString(celFilterExpression) {
		analytics.TrackCommandScanFilterArgs()

		task, err := analyzer.NewCelFilterAnalyzer(celFilterExpression,
			failFast || celFilterFailOnMatch)
		if err != nil {
			return err
		}

		analyzers = append(analyzers, task)
	}

	if !utils.IsEmptyString(celFilterSuiteFile) {
		analytics.TrackCommandScanFilterSuite()

		task, err := analyzer.NewCelFilterSuiteAnalyzer(celFilterSuiteFile,
			failFast || celFilterFailOnMatch)
		if err != nil {
			return err
		}

		analyzers = append(analyzers, task)
	}

	if enrichMalware || enrichMalwareQuery {
		config := analyzer.DefaultMalwareAnalyzerConfig()
		config.TrustAutomatedAnalysis = malwareAnalyzerTrustToolResult
		config.MinimumConfidence = malwareAnalysisMinimumConfidence
		config.FailFast = failFast

		task, err := analyzer.NewMalwareAnalyzer(config)
		if err != nil {
			return err
		}

		analyzers = append(analyzers, task)
	}

	reporters := []reporter.Reporter{}
	if consoleReport {
		rp, err := reporter.NewConsoleReporter()
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if summaryReport {
		rp, err := reporter.NewSummaryReporter(reporter.SummaryReporterConfig{
			MaxAdvice:                    summaryReportMaxAdvice,
			GroupByDirectDependency:      summaryReportGroupByDirectDeps,
			ShowOnlyPackagesWithEvidence: summaryReportUsedOnly,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(markdownReportPath) {
		rp, err := reporter.NewMarkdownReportGenerator(reporter.MarkdownReportingConfig{
			Path: markdownReportPath,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(markdownSummaryReportPath) {
		analytics.TrackReporterMarkdownSummary()

		rp, err := reporter.NewMarkdownSummaryReporter(reporter.MarkdownSummaryReporterConfig{
			Tool:                   toolMetadata,
			Path:                   markdownSummaryReportPath,
			IncludeMalwareAnalysis: true,
			ActiveMalwareAnalysis:  enrichMalware,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(jsonReportPath) {
		analytics.TrackReporterJSON()

		rp, err := reporter.NewJsonReportGenerator(reporter.JsonReportingConfig{
			Path: jsonReportPath,
			Tool: toolMetadata,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(sarifReportPath) {
		analytics.TrackReporterSarif()

		rp, err := reporter.NewSarifReporter(reporter.SarifReporterConfig{
			Tool:           toolMetadata,
			IncludeVulns:   sarifIncludeVulns,
			IncludeMalware: sarifIncludeMalware,
			Path:           sarifReportPath,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(cyclonedxReportPath) {
		analytics.TrackReporterCycloneDX()

		if utils.IsEmptyString(cyclonedxReportApplicationName) {
			cyclonedxReportApplicationName, err = reader.ApplicationName()
			if err != nil {
				return err
			}
		}

		rp, err := reporter.NewCycloneDXReporter(reporter.CycloneDXReporterConfig{
			Tool:                     toolMetadata,
			Path:                     cyclonedxReportPath,
			ApplicationComponentName: cyclonedxReportApplicationName,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if reportDefectDojo {
		analytics.TrackReporterDefectDojo()

		defectDojoApiV2Key := os.Getenv("DEFECT_DOJO_APIV2_KEY")
		if utils.IsEmptyString(defectDojoApiV2Key) {
			return fmt.Errorf("please set DEFECT_DOJO_APIV2_KEY environment variable to enable defect-dojo reporting")
		}

		engagementName := fmt.Sprintf("vet-report-%s", time.Now().Format("2006-01-02"))
		rp, err := reporter.NewDefectDojoReporter(reporter.DefectDojoReporterConfig{
			Tool:               toolMetadata,
			IncludeVulns:       true,
			IncludeMalware:     true,
			ProductID:          defectDojoProductID,
			EngagementName:     engagementName,
			DefectDojoHostUrl:  defectDojoHostUrl,
			DefectDojoApiV2Key: defectDojoApiV2Key,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(graphReportDirectory) {
		rp, err := reporter.NewDotGraphReporter(graphReportDirectory)
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(csvReportPath) {
		analytics.TrackReporterCSV()

		rp, err := reporter.NewCsvReporter(reporter.CsvReportingConfig{
			Path: csvReportPath,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(gitlabReportPath) {
		rp, err := reporter.NewGitLabReporter(reporter.GitLabReporterConfig{
			Path: gitlabReportPath,
			Tool: toolMetadata,
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	if !utils.IsEmptyString(sqlite3ReportPath) {
		rp, err := reporter.NewSqlite3Reporter(reporter.Sqlite3ReporterConfig{
			Path:      sqlite3ReportPath,
			Tool:      toolMetadata,
			Overwrite: sqlite3ReportOverwrite,
			Append:    sqlite3ReportAppend,
		})
		if err != nil {
			return fmt.Errorf("%w: Use --report-sqlite3-overwrite or --report-sqlite3-append overwrite or append", err)
		}

		reporters = append(reporters, rp)
	}

	// UI tracker (progress bar) for cloud report syncing
	var syncReportTracker any

	if syncReport {
		analytics.TrackReporterCloudSync()

		clientConn, err := auth.SyncClientConnection("vet-sync")
		if err != nil {
			return err
		}

		rp, err := reporter.NewSyncReporter(reporter.SyncReporterConfig{
			Tool:                   toolMetadata,
			ProjectName:            syncReportProject,
			ProjectVersion:         syncReportStream,
			EnableMultiProjectSync: syncEnableMultiProject,
			ClientConnection:       clientConn,
		}, reporter.NewSyncReporterEnvironmentResolver(), reporter.SyncReporterCallbacks{
			OnSyncStart: func() {
				ui.PrintMsg("🌐 Syncing data to SafeDep Cloud...")
			},
			OnPackageSync: func(pkg *models.Package) {
				ui.IncrementTrackerTotal(syncReportTracker, 1)
			},
			OnPackageSyncDone: func(pkg *models.Package) {
				ui.IncrementProgress(syncReportTracker, 1)
			},
			OnEventSync: func(event *analyzer.AnalyzerEvent) {
				ui.IncrementTrackerTotal(syncReportTracker, 1)
			},
			OnEventSyncDone: func(event *analyzer.AnalyzerEvent) {
				ui.IncrementProgress(syncReportTracker, 1)
			},
			OnSyncFinish: func() {
				ui.PrintSuccess("Syncing report data to cloud is complete")
			},
		})
		if err != nil {
			return err
		}

		reporters = append(reporters, rp)
	}

	enrichers := []scanner.PackageMetaEnricher{}
	if enrich {
		var enricher scanner.PackageMetaEnricher
		if enrichUsingInsightsV2 {
			analytics.TrackCommandScanInsightsV2()

			var client *grpc.ClientConn
			var err error

			// We have two endpoints for accessing the insights v2 service. The authenticated endpoints
			// have higher rate limits and better latency guarantees
			if auth.CommunityMode() {
				client, err = auth.InsightsV2CommunityClientConnection("vet-insights-v2")
			} else {
				client, err = auth.InsightsV2ClientConnection("vet-insights-v2")
			}

			if err != nil {
				return err
			}

			insightsV2Enricher, err := scanner.NewInsightBasedPackageEnricherV2(client)
			if err != nil {
				return err
			}

			ui.PrintMsg("Using Insights v2 for package metadata enrichment")
			enricher = insightsV2Enricher
		} else {
			insightsEnricher, err := scanner.NewInsightBasedPackageEnricher(scanner.InsightsBasedPackageMetaEnricherConfig{
				ApiUrl:     auth.ApiUrl(),
				ApiAuthKey: auth.ApiKey(),
			})
			if err != nil {
				return err
			}

			enricher = insightsEnricher
		}

		enrichers = append(enrichers, enricher)
	}

	if codeAnalysisDBPath != "" {
		analytics.TrackCommandScanUsingCodeAnalysis()

		entSqliteStorage, err := storage.NewEntSqliteStorage(storage.EntSqliteClientConfig{
			Path:               codeAnalysisDBPath,
			ReadOnly:           true,
			SkipSchemaCreation: false,
		})
		if err != nil {
			return err
		}

		readerClient, err := entSqliteStorage.Client()
		if err != nil {
			return err
		}

		readerRepository, err := code.NewReaderRepository(readerClient)
		if err != nil {
			return err
		}

		codeAnalysisEnricher := scanner.NewCodeAnalysisEnricher(
			scanner.CodeAnalysisEnricherConfig{
				EnableDepsUsageEvidence: dependencyUsageEvidence,
			},
			readerRepository,
		)
		enrichers = append(enrichers, codeAnalysisEnricher)
	}

	if enrichMalware {
		analytics.TrackCommandScanMalwareAnalysis()

		if auth.CommunityMode() {
			return fmt.Errorf("access to Malicious Package Analysis requires an API key. " +
				"For more details: https://docs.safedep.io/cloud/quickstart/")
		}

		client, err := auth.MalwareAnalysisClientConnection("vet-malware-analysis")
		if err != nil {
			return err
		}

		config := scanner.DefaultMalysisMalwareEnricherConfig()
		config.Timeout = malwareAnalysisTimeout

		malwareEnricher, err := scanner.NewMalysisMalwareEnricher(client, githubClient, config)
		if err != nil {
			return err
		}

		ui.PrintMsg("Using Malysis for malware analysis")
		enrichers = append(enrichers, malwareEnricher)
	} else if enrichMalwareQuery {
		// If active analysis is not enable, we will use the query enricher to
		// query known malicious packages data from the Malysis service. This is
		// the default behavior unless explicitly disabled by user.
		client, err := auth.MalwareAnalysisCommunityClientConnection("vet-malware-analysis")
		if err != nil {
			return err
		}

		config := scanner.DefaultMalysisMalwareEnricherConfig()
		config.Timeout = malwareAnalysisTimeout

		queryEnricher, err := scanner.NewMalysisMalwareAnalysisQueryEnricher(client, githubClient, config)
		if err != nil {
			return err
		}

		enrichers = append(enrichers, queryEnricher)
	}

	pmScanner := scanner.NewPackageManifestScanner(scanner.Config{
		TransitiveAnalysis: transitiveAnalysis,
		TransitiveDepth:    transitiveDepth,
		ConcurrentAnalyzer: concurrency,
		ExcludePatterns:    scanExclude,
		Experimental:       scannerExperimental,
	}, readerList, enrichers, analyzers, reporters)

	// Redirect log to files to create space for UI rendering
	redirectLogToFile(logFile)

	// Trackers to handle UI
	var packageManifestTracker any
	var packageTracker any

	manifestsCount := 0
	pmScanner.WithCallbacks(scanner.ScannerCallbacks{
		OnStartEnumerateManifest: func() {
			logger.Infof("Starting to enumerate manifests")
		},
		OnEnumerateManifest: func(manifest *models.PackageManifest) {
			logger.Infof("Discovered a manifest at %s with %d packages",
				manifest.GetDisplayPath(), manifest.GetPackagesCount())

			ui.IncrementTrackerTotal(packageManifestTracker, 1)
			ui.IncrementTrackerTotal(packageTracker, int64(manifest.GetPackagesCount()))

			manifestsCount = manifestsCount + 1
			ui.SetPinnedMessageOnProgressWriter(fmt.Sprintf("Scanning %d discovered manifest(s)",
				manifestsCount))
		},
		OnStart: func() {
			if !silentScan {
				ui.StartProgressWriter()
			}

			packageManifestTracker = ui.TrackProgress("Scanning manifests", 0)
			packageTracker = ui.TrackProgress("Scanning packages", 0)

			// We use a separate tracker for syncing report data
			if syncReport {
				syncReportTracker = ui.TrackProgress("Uploading reports", 0)
			}
		},
		OnAddTransitivePackage: func(pkg *models.Package) {
			ui.IncrementTrackerTotal(packageTracker, 1)
		},
		OnDoneManifest: func(manifest *models.PackageManifest) {
			ui.IncrementProgress(packageManifestTracker, 1)
		},
		OnDonePackage: func(pkg *models.Package) {
			ui.IncrementProgress(packageTracker, 1)
		},
		BeforeFinish: func() {
			// Only mark package and manifest trackers as done
			ui.MarkTrackerAsDone(packageManifestTracker)
			ui.MarkTrackerAsDone(packageTracker)
		},
		OnStop: func(err error) {
			if syncReport {
				ui.MarkTrackerAsDone(syncReportTracker)
			}

			ui.StopProgressWriter()
		},
	})

	return pmScanner.Start()
}
