package analytics

const (
	eventRun = "command_run"

	eventCommandQuery     = "command_query"
	eventCommandScan      = "command_scan"
	eventCommandImageScan = "command_image_scan"

	eventScanFilterSuite         = "command_scan_has_filter_suite"
	eventScanFilterArgs          = "command_scan_has_filter_args"
	eventScanInsightsV2          = "command_scan_insights_v2"
	eventScanMalwareAnalysis     = "command_scan_malware_analysis"
	eventScanPackageManifestScan = "command_scan_manifest_scan"
	eventScanDirectoryScan       = "command_scan_directory_scan"
	eventScanPurlScan            = "command_scan_purl_scan"
	eventScanGitHubScan          = "command_scan_github_scan"
	eventScanGitHubOrgScan       = "command_scan_github_org_scan"
	eventScanVSCodeExtScan       = "command_scan_vscode_ext_scan"
	eventScanUsingCodeAnalysis   = "command_scan_using_code_analysis"
	eventScanEnvCI               = "command_scan_env_ci"
	eventScanEnvDocker           = "command_scan_env_docker"
	eventScanEnvGitHubActions    = "command_scan_env_github_actions"
	eventScanEnvGitLabCI         = "command_scan_env_gitlab_ci"
	eventScanBrewScan            = "command_scan_brew_scan"

	eventInspectMalwareAnalysis = "command_inspect_malware_analysis"

	eventReporterMarkdownSummary = "reporter_markdown_summary"
	eventReporterJSON            = "reporter_json"
	eventReporterCloudSync       = "reporter_cloud_sync"
	eventReporterDefectDojo      = "reporter_defect_dojo"
	eventReporterSarif           = "reporter_sarif"
	eventReporterCycloneDX       = "reporter_cyclonedx"
	eventReporterCSV             = "reporter_csv"

	eventAgentQuery = "agent_query"
)

func TrackCommandRun() {
	TrackEvent(eventRun)
}

func TrackCommandQuery() {
	TrackEvent(eventCommandQuery)
}

func TrackCommandScan() {
	TrackEvent(eventCommandScan)
}

func TrackCommandScanFilterSuite() {
	TrackEvent(eventScanFilterSuite)
}

func TrackCommandScanFilterArgs() {
	TrackEvent(eventScanFilterArgs)
}

func TrackCommandScanInsightsV2() {
	TrackEvent(eventScanInsightsV2)
}

func TrackCommandScanMalwareAnalysis() {
	TrackEvent(eventScanMalwareAnalysis)
}

func TrackCommandScanPackageManifestScan() {
	TrackEvent(eventScanPackageManifestScan)
}

func TrackCommandScanDirectoryScan() {
	TrackEvent(eventScanDirectoryScan)
}

func TrackCommandScanPurlScan() {
	TrackEvent(eventScanPurlScan)
}

func TrackCommandScanVSCodeExtScan() {
	TrackEvent(eventScanVSCodeExtScan)
}

func TrackCommandScanGitHubScan() {
	TrackEvent(eventScanGitHubScan)
}

func TrackCommandScanGitHubOrgScan() {
	TrackEvent(eventScanGitHubOrgScan)
}

func TrackCommandScanUsingCodeAnalysis() {
	TrackEvent(eventScanUsingCodeAnalysis)
}

func TrackCommandScanEnvCI() {
	TrackEvent(eventScanEnvCI)
}

func TrackCommandScanEnvDocker() {
	TrackEvent(eventScanEnvDocker)
}

func TrackCommandScanEnvGitHubActions() {
	TrackEvent(eventScanEnvGitHubActions)
}

func TrackCommandScanEnvGitLabCI() {
	TrackEvent(eventScanEnvGitLabCI)
}

func TrackCommandInspectMalwareAnalysis() {
	TrackEvent(eventInspectMalwareAnalysis)
}

func TrackReporterMarkdownSummary() {
	TrackEvent(eventReporterMarkdownSummary)
}

func TrackReporterJSON() {
	TrackEvent(eventReporterJSON)
}

func TrackReporterCloudSync() {
	TrackEvent(eventReporterCloudSync)
}

func TrackReporterDefectDojo() {
	TrackEvent(eventReporterDefectDojo)
}

func TrackReporterSarif() {
	TrackEvent(eventReporterSarif)
}

func TrackReporterCycloneDX() {
	TrackEvent(eventReporterCycloneDX)
}

func TrackReporterCSV() {
	TrackEvent(eventReporterCSV)
}

func TrackCommandImageScan() {
	TrackEvent(eventCommandImageScan)
}

func TrackAgentQuery() {
	TrackEvent(eventAgentQuery)
}

func TrackCommandScanBrewScan() {
	TrackEvent(eventScanBrewScan)
}
