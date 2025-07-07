package reporter

import (
	"context"
	"fmt"
	"strconv"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
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
		SetDescription(""). // No details field in v1 vulnerability, using summary as title
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
