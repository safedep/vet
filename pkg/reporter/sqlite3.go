package reporter

import (
	"context"
	"fmt"
	"strconv"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	scorecardv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/scorecard/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	"github.com/safedep/vet/ent"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/storage"
)

type Sqlite3ReporterConfig struct {
	Path string
	Tool ToolMetadata
}

type sqlite3Reporter struct {
	config  Sqlite3ReporterConfig
	client  *ent.Client
	storage storage.Storage[*ent.Client]

	manifestCache map[string]*ent.ReportPackageManifest
	packageCache  map[string]*ent.ReportPackage
}

func NewSqlite3Reporter(config Sqlite3ReporterConfig) (Reporter, error) {
	entStorage, err := storage.NewEntSqliteStorage(storage.EntSqliteClientConfig{
		Path:               config.Path,
		ReadOnly:           false,
		SkipSchemaCreation: false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create SQLite storage: %w", err)
	}

	client, err := entStorage.Client()
	if err != nil {
		return nil, fmt.Errorf("failed to get Ent client: %w", err)
	}

	return &sqlite3Reporter{
		config:        config,
		client:        client,
		storage:       entStorage,
		manifestCache: make(map[string]*ent.ReportPackageManifest),
		packageCache:  make(map[string]*ent.ReportPackage),
	}, nil
}

func (r *sqlite3Reporter) Name() string {
	return "SQLite3 Database Reporter"
}

func (r *sqlite3Reporter) AddManifest(manifest *models.PackageManifest) {
	now := time.Now()
	manifestID := manifest.Id()

	ctx := context.Background()

	// Check if manifest already exists in cache
	if _, exists := r.manifestCache[manifestID]; exists {
		return
	}

	// Create manifest in database
	entManifest, err := r.client.ReportPackageManifest.Create().
		SetManifestID(manifestID).
		SetSourceType(string(manifest.GetSource().GetType())).
		SetNamespace(manifest.GetSource().GetNamespace()).
		SetPath(manifest.GetSource().GetPath()).
		SetDisplayPath(manifest.GetDisplayPath()).
		SetEcosystem(manifest.Ecosystem).
		SetCreatedAt(now).
		SetUpdatedAt(now).
		Save(ctx)
	if err != nil {
		logger.Errorf("Failed to create manifest in database: %v", err)
		return
	}

	r.manifestCache[manifestID] = entManifest

	// Process packages in manifest
	for _, pkg := range manifest.GetPackages() {
		r.addPackage(pkg, entManifest)
	}
}

func (r *sqlite3Reporter) addPackage(pkg *models.Package, manifest *ent.ReportPackageManifest) {
	now := time.Now()
	packageID := pkg.Id()
	ctx := context.Background()

	// Check if package already exists in cache
	if _, exists := r.packageCache[packageID]; exists {
		return
	}

	// Create package in database
	entPackage, err := r.client.ReportPackage.Create().
		SetPackageID(packageID).
		SetName(pkg.GetName()).
		SetVersion(pkg.GetVersion()).
		SetEcosystem(string(pkg.Ecosystem)).
		SetPackageURL(pkg.GetPackageUrl()).
		SetDepth(pkg.Depth).
		SetIsDirect(pkg.IsDirect()).
		SetIsMalware(pkg.IsMalware()).
		SetIsSuspicious(pkg.IsSuspicious()).
		SetManifest(manifest).
		SetCreatedAt(now).
		SetUpdatedAt(now).
		Save(ctx)
	if err != nil {
		logger.Errorf("Failed to create package in database: %v", err)
		return
	}

	r.packageCache[packageID] = entPackage

	// Add package details as JSON if available
	if pkg.PackageDetails.Name != "" {
		packageDetails := map[string]interface{}{
			"ecosystem":  string(pkg.PackageDetails.Ecosystem),
			"name":       pkg.PackageDetails.Name,
			"version":    pkg.PackageDetails.Version,
			"compare_as": string(pkg.PackageDetails.CompareAs),
			"commit":     pkg.PackageDetails.Commit,
		}
		entPackage.Update().SetPackageDetails(packageDetails).ExecX(ctx)
	}

	// Add Insights v2 data if available
	if pkg.InsightsV2 != nil {
		r.addInsightsV2Data(entPackage, pkg.InsightsV2)
	}

	// Add code analysis data if available
	if pkg.CodeAnalysis != nil {
		codeAnalysisData := map[string]interface{}{
			"usage_evidences": pkg.CodeAnalysis.UsageEvidences,
		}
		entPackage.Update().SetCodeAnalysis(codeAnalysisData).ExecX(ctx)
	}

	// Add malware analysis if available
	if pkg.MalwareAnalysis != nil {
		r.addMalwareAnalysis(entPackage, pkg.MalwareAnalysis)
	}

	// Add dependency graph information
	r.addDependencies(entPackage, pkg)

	// Add dependency graph edges
	r.addDependencyGraphEdges(entPackage, pkg, manifest)
}

func (r *sqlite3Reporter) addInsightsV2Data(entPackage *ent.ReportPackage, insights *packagev1.PackageVersionInsight) {
	ctx := context.Background()

	// Store the full insights as JSON - this is simpler and more robust
	// Users can query the JSON data directly for detailed analysis
	insightsData := map[string]interface{}{
		"deprecated":      insights.Deprecated,
		"vulnerabilities": insights.Vulnerabilities,
		"licenses":        insights.Licenses,
		"dependencies":    insights.Dependencies,
		// Add other fields as needed
	}
	entPackage.Update().SetInsightsV2(insightsData).ExecX(ctx)

	// Extract and store vulnerabilities in structured format for easier querying
	if insights.Vulnerabilities != nil {
		for _, vuln := range insights.Vulnerabilities {
			r.addVulnerability(entPackage, vuln)
		}
	}

	// Extract and store licenses in structured format for easier querying
	if insights.Licenses != nil && insights.Licenses.Licenses != nil {
		for _, license := range insights.Licenses.Licenses {
			r.addLicense(entPackage, license)
		}
	}

	// Extract and store project information including scorecard data
	if insights.ProjectInsights != nil {
		for _, projectInsight := range insights.ProjectInsights {
			r.addProjectInsight(entPackage, projectInsight)
		}
	}
}

func (r *sqlite3Reporter) addVulnerability(entPackage *ent.ReportPackage, vuln *vulnerabilityv1.Vulnerability) {
	now := time.Now()
	ctx := context.Background()

	// Extract vulnerability ID
	vulnID := ""
	if vuln.Id != nil {
		vulnID = vuln.Id.Value
	}
	if vulnID == "" {
		return
	}

	// Extract aliases
	aliases := []string{}
	for _, alias := range vuln.Aliases {
		if alias != nil {
			aliases = append(aliases, alias.Value)
		}
	}

	// Extract severity information
	var severity, severityType string
	var cvssScore float64
	var severityDetails map[string]interface{}

	if len(vuln.Severities) > 0 {
		firstSeverity := vuln.Severities[0]

		// Map severity risk enum to string
		switch firstSeverity.Risk {
		case vulnerabilityv1.Severity_RISK_CRITICAL:
			severity = "CRITICAL"
		case vulnerabilityv1.Severity_RISK_HIGH:
			severity = "HIGH"
		case vulnerabilityv1.Severity_RISK_MEDIUM:
			severity = "MEDIUM"
		case vulnerabilityv1.Severity_RISK_LOW:
			severity = "LOW"
		default:
			severity = "UNKNOWN"
		}

		// Map severity type enum to string
		switch firstSeverity.Type {
		case vulnerabilityv1.Severity_TYPE_CVSS_V2:
			severityType = "CVSS_V2"
		case vulnerabilityv1.Severity_TYPE_CVSS_V3:
			severityType = "CVSS_V3"
		default:
			severityType = "UNSPECIFIED"
		}

		// Parse CVSS score
		if score, err := strconv.ParseFloat(firstSeverity.Score, 64); err == nil {
			cvssScore = score
		}

		// Store all severity details as JSON
		severityDetails = map[string]interface{}{
			"severities": vuln.Severities,
		}
	}

	// Create vulnerability record
	_, err := r.client.ReportVulnerability.Create().
		SetVulnerabilityID(vulnID).
		SetTitle(vuln.Summary).
		SetAliases(aliases).
		SetSeverity(severity).
		SetSeverityType(severityType).
		SetCvssScore(cvssScore).
		SetSeverityDetails(severityDetails).
		SetPackage(entPackage).
		SetCreatedAt(now).
		SetUpdatedAt(now).
		Save(ctx)
	if err != nil {
		logger.Errorf("Failed to create vulnerability in database: %v", err)
	}
}

func (r *sqlite3Reporter) addLicense(entPackage *ent.ReportPackage, license *packagev1.LicenseMeta) {
	now := time.Now()
	ctx := context.Background()

	// Extract license ID - this is the primary identifier
	licenseID := license.LicenseId
	if licenseID == "" {
		return
	}

	// Create license record
	// Note: LicenseMeta only has LicenseId and Name fields
	// Other fields like SpdxId, Url, IsOsiApproved are not available in v2 model
	_, err := r.client.ReportLicense.Create().
		SetLicenseID(licenseID).
		SetName(license.Name).
		SetSpdxID(licenseID).
		SetURL(license.DetailsUrl).
		SetIsOsiApproved(license.OsiApproved).
		SetIsFsfApproved(license.FsfApproved).
		SetIsSaasCompatible(license.SaasCompatible).
		SetIsCommercialUseAllowed(license.CommercialUseAllowed).
		SetPackage(entPackage).
		SetCreatedAt(now).
		SetUpdatedAt(now).
		Save(ctx)
	if err != nil {
		logger.Errorf("Failed to create license in database: %v", err)
	}
}

func (r *sqlite3Reporter) addProjectInsight(entPackage *ent.ReportPackage, projectInsight *packagev1.ProjectInsight) {
	now := time.Now()
	ctx := context.Background()

	if projectInsight.Project == nil {
		return
	}

	project := projectInsight.Project

	// Extract project information
	projectName := project.Name
	projectURL := project.Url
	projectDescription := "" // Description is not available in v2 model
	
	// Handle optional fields safely
	var stars, forks int32
	if projectInsight.Stars != nil {
		stars = int32(*projectInsight.Stars)
	}
	if projectInsight.Forks != nil {
		forks = int32(*projectInsight.Forks)
	}

	// Create project record
	entProject, err := r.client.ReportProject.Create().
		SetName(projectName).
		SetNillableURL(&projectURL).
		SetNillableDescription(&projectDescription).
		SetNillableStars(&stars).
		SetNillableForks(&forks).
		SetPackage(entPackage).
		SetCreatedAt(now).
		SetUpdatedAt(now).
		Save(ctx)
	if err != nil {
		logger.Errorf("Failed to create project in database: %v", err)
		return
	}

	// Create scorecard record if available
	if projectInsight.Scorecard != nil {
		r.addScorecard(entProject, projectInsight.Scorecard)
	}
}

func (r *sqlite3Reporter) addScorecard(entProject *ent.ReportProject, scorecard *scorecardv1.Scorecard) {
	now := time.Now()
	ctx := context.Background()

	// Extract scorecard information
	score := scorecard.Score
	version := scorecard.ScorecardVersion.Version
	repoName := scorecard.Repo.Name
	repoCommit := scorecard.Repo.Commit
	date := scorecard.Date

	// Create scorecard record
	entScorecard, err := r.client.ReportScorecard.Create().
		SetScore(score).
		SetScorecardVersion(version).
		SetRepoName(repoName).
		SetRepoCommit(repoCommit).
		SetDate(date).
		SetProject(entProject).
		SetCreatedAt(now).
		SetUpdatedAt(now).
		Save(ctx)
	if err != nil {
		logger.Errorf("Failed to create scorecard in database: %v", err)
		return
	}

	// Create scorecard check records
	for _, check := range scorecard.Checks {
		r.addScorecardCheck(entScorecard, check)
	}
}

func (r *sqlite3Reporter) addScorecardCheck(entScorecard *ent.ReportScorecard, check *scorecardv1.ScorecardCheck) {
	now := time.Now()
	ctx := context.Background()

	// Create scorecard check record
	create := r.client.ReportScorecardCheck.Create().
		SetName(check.Name).
		SetScore(check.Score).
		SetScorecard(entScorecard).
		SetCreatedAt(now).
		SetUpdatedAt(now)
	
	// Set reason if available (it's optional)
	if check.Reason != nil {
		create = create.SetReason(*check.Reason)
	}
	
	_, err := create.Save(ctx)
	if err != nil {
		logger.Errorf("Failed to create scorecard check in database: %v", err)
	}
}

func (r *sqlite3Reporter) addMalwareAnalysis(entPackage *ent.ReportPackage, malware *models.MalwareAnalysisResult) {
	now := time.Now()
	ctx := context.Background()

	// Prepare report and verification record as JSON
	var reportData, verificationData map[string]interface{}
	if malware.Report != nil {
		reportData = map[string]interface{}{
			"report": malware.Report,
		}
	}
	if malware.VerificationRecord != nil {
		verificationData = map[string]interface{}{
			"verification_record": malware.VerificationRecord,
		}
	}

	_, err := r.client.ReportMalware.Create().
		SetAnalysisID(malware.AnalysisId).
		SetIsMalware(malware.IsMalware).
		SetIsSuspicious(malware.IsSuspicious).
		SetReport(reportData).
		SetVerificationRecord(verificationData).
		SetPackage(entPackage).
		SetCreatedAt(now).
		SetUpdatedAt(now).
		Save(ctx)
	if err != nil {
		logger.Errorf("Failed to create malware analysis in database: %v", err)
	}
}

func (r *sqlite3Reporter) addDependencies(entPackage *ent.ReportPackage, pkg *models.Package) {
	dependencies, err := pkg.GetDependencies()
	if err != nil {
		// No dependencies available
		return
	}

	ctx := context.Background()
	now := time.Now()

	for _, dep := range dependencies {
		_, err := r.client.ReportDependency.Create().
			SetDependencyPackageID(dep.Id()).
			SetDependencyName(dep.GetName()).
			SetDependencyVersion(dep.GetVersion()).
			SetDependencyEcosystem(string(dep.Ecosystem)).
			SetDepth(dep.Depth).
			SetPackage(entPackage).
			SetCreatedAt(now).
			SetUpdatedAt(now).
			Save(ctx)
		if err != nil {
			logger.Errorf("Failed to create dependency in database: %v", err)
		}
	}
}

func (r *sqlite3Reporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	// For SQLite3 reporter, we focus on storing the core package data
	// Analyzer events like filter matches could be stored as additional metadata
	// For now, we'll skip these as the main package data is more important
}

func (r *sqlite3Reporter) AddPolicyEvent(event *policy.PolicyEvent) {
	// Policy events can be stored as additional metadata if needed
	// For now, we'll skip these as the main package data is more important
}

func (r *sqlite3Reporter) addDependencyGraphEdges(entPackage *ent.ReportPackage, pkg *models.Package, manifest *ent.ReportPackageManifest) {
	ctx := context.Background()
	now := time.Now()

	// Get the dependency graph if available
	dependencyGraph := pkg.GetDependencyGraph()
	if dependencyGraph == nil || !dependencyGraph.Present() {
		return
	}

	// Find the node for this package in the dependency graph
	var currentNode *models.DependencyGraphNode[*models.Package]
	nodes := dependencyGraph.GetNodes()
	for _, node := range nodes {
		if node.Data.Id() == pkg.Id() {
			currentNode = node
			break
		}
	}

	if currentNode == nil {
		return
	}

	// Create edges for all dependencies of this package
	for _, depPkg := range currentNode.Children {
		// Skip if the dependency package is the same as current package (cycle detection)
		if depPkg.Id() == pkg.Id() {
			continue
		}

		// Determine if this is a direct dependency
		isDirect := pkg.Depth == 0 || depPkg.Depth == pkg.Depth+1

		// Create dependency graph edge
		_, err := r.client.ReportDependencyGraph.Create().
			SetFromPackageID(pkg.Id()).
			SetFromPackageName(pkg.GetName()).
			SetFromPackageVersion(pkg.GetVersion()).
			SetFromPackageEcosystem(string(pkg.Ecosystem)).
			SetToPackageID(depPkg.Id()).
			SetToPackageName(depPkg.GetName()).
			SetToPackageVersion(depPkg.GetVersion()).
			SetToPackageEcosystem(string(depPkg.Ecosystem)).
			SetDepth(depPkg.Depth).
			SetIsDirect(isDirect).
			SetIsRootEdge(pkg.Depth == 0).
			SetManifestID(manifest.ManifestID).
			SetCreatedAt(now).
			SetUpdatedAt(now).
			Save(ctx)
		if err != nil {
			logger.Errorf("Failed to create dependency graph edge: %v", err)
		}
	}

	// Also create edges from Insights V2 dependencies if available
	if pkg.InsightsV2 != nil && pkg.InsightsV2.Dependencies != nil {
		for _, dep := range pkg.InsightsV2.Dependencies {
			if dep.Package == nil {
				continue
			}

			depID := models.ControlTowerPackageID(dep)

			// Skip if the dependency package is the same as current package
			if depID == pkg.Id() {
				continue
			}

			// Create dependency graph edge from Insights V2 data
			_, err := r.client.ReportDependencyGraph.Create().
				SetFromPackageID(pkg.Id()).
				SetFromPackageName(pkg.GetName()).
				SetFromPackageVersion(pkg.GetVersion()).
				SetFromPackageEcosystem(string(pkg.Ecosystem)).
				SetToPackageID(depID).
				SetToPackageName(dep.Package.Name).
				SetToPackageVersion(dep.Version).
				SetToPackageEcosystem(string(dep.Package.Ecosystem)).
				SetDepth(1). // Insights V2 dependencies are typically direct
				SetIsDirect(true).
				SetIsRootEdge(pkg.Depth == 0).
				SetManifestID(manifest.ManifestID).
				SetCreatedAt(now).
				SetUpdatedAt(now).
				Save(ctx)
			if err != nil {
				logger.Errorf("Failed to create dependency graph edge from Insights V2: %v", err)
			}
		}
	}
}

func (r *sqlite3Reporter) Finish() error {
	logger.Infof("Finalizing SQLite3 database report: %s", r.config.Path)

	// Close the database connection
	if r.client != nil {
		if err := r.client.Close(); err != nil {
			logger.Errorf("Failed to close database client: %v", err)
		}
	}

	logger.Infof("SQLite3 database report generated successfully: %s", r.config.Path)
	return nil
}
