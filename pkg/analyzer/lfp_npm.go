package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	jsonreportspec "github.com/safedep/vet/gen/jsonreport"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/utils"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
)

const npmRegistryTrustedUrlBase = "https://registry.npmjs.org"

type npmPackageLockPackage struct {
	Version   string `json:"version"`
	License   string `json:"license"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
	Optional  bool   `json:"optional"`
	Link      bool   `json:"link"`
}

// https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
type npmPackageLock struct {
	Name            string                           `json:"name"`
	Version         string                           `json:"version"`
	LockfileVersion int                              `json:"lockfileVersion"`
	Packages        map[string]npmPackageLockPackage `json:"packages"`
}

type npmLockfilePoisoningAnalyzer struct {
	config LockfilePoisoningAnalyzerConfig
}

func (npm *npmLockfilePoisoningAnalyzer) Analyze(manifest *models.PackageManifest,
	handler AnalyzerEventHandler) error {
	logger.Debugf("npmLockfilePoisoningAnalyzer: Analyzing [%s] %s",
		manifest.GetSpecEcosystem(), manifest.GetDisplayPath())

	data, err := os.ReadFile(manifest.GetPath())
	if err != nil {
		return err
	}

	var lockfile npmPackageLock
	err = json.NewDecoder(bytes.NewReader(data)).Decode(&lockfile)
	if err != nil {
		return err
	}

	if lockfile.LockfileVersion < 2 {
		return fmt.Errorf("npmLockfilePoisoningAnalyzer: Unsupported lockfile version %d",
			lockfile.LockfileVersion)
	}

	logger.Debugf("npmLockfilePoisoningAnalyzer: Found %d packages in lockfile",
		len(lockfile.Packages))

	// Build a map of packages to query by name
	pkgMap := map[string]*models.Package{}
	err = readers.NewManifestModelReader(manifest).EnumPackages(func(p *models.Package) error {
		pkgMap[p.Name] = p
		return nil
	})

	if err != nil {
		return err
	}

	logger.Debugf("npmLockfilePoisoningAnalyzer: Found %d packages in manifest", len(pkgMap))

	// Poisoning can happen in the following cases:
	// 1. If the package is fetched from an untrusted host
	// 2. If the package path on filesystem does not match the URL path convention
	// 3. If a new entry is added to package-lock.json dependency list
	for path, lockfilePackage := range lockfile.Packages {
		// The root package is not a dependency, it is the application itself
		if path == "" {
			logger.Debugf("npmLockfilePoisoningAnalyzer: Skipping root package")
			continue
		}

		if lockfilePackage.Resolved == "" {
			logger.Warnf("npmLockfilePoisoningAnalyzer: Node Module [%s] does not have a resolved URL", path)
			continue
		}

		if lockfilePackage.Link {
			logger.Debugf("npmLockfilePoisoningAnalyzer: Skipping linked package [%s] for [%s]",
				path, lockfilePackage.Resolved)
			continue
		}

		packageName := npmNodeModulesPackagePathToName(path)
		if packageName == "" {
			logger.Warnf("npmLockfilePoisoningAnalyzer: Failed to extract package name from path %s", path)
			continue
		}

		// We don't strictly need this because the package name is extracted from `package-lock.json`
		// The impact here is, pkg can be nil in the event and may cause a bug for reporters if they
		// don't handle nil package
		pkg, ok := pkgMap[packageName]
		if !ok {
			logger.Debugf("npmLockfilePoisoningAnalyzer: Package [%s] not found in manifest", packageName)
		}

		trustedRegistryUrls := []string{npmRegistryTrustedUrlBase}
		trustedRegistryUrls = append(trustedRegistryUrls, npm.config.TrustedRegistryUrls...)
		userTrustUrls := npm.config.TrustedRegistryUrls
		logger.Debugf("npmLockfilePoisoningAnalyzer: Analyzing package [%s] with %d trusted registry URLs in config",
			packageName, len(trustedRegistryUrls))

		if !npmIsTrustedSource(lockfilePackage.Resolved, trustedRegistryUrls) {
			logger.Debugf("npmLockfilePoisoningAnalyzer: Package [%s] resolved to an untrusted host [%s]",
				packageName, lockfilePackage.Resolved)

			message := fmt.Sprintf("Package `%s` resolved to an untrusted host `%s`",
				packageName, lockfilePackage.Resolved)

			_ = handler(&AnalyzerEvent{
				Source:   lfpAnalyzerName,
				Type:     ET_LockfilePoisoningSignal,
				Message:  message,
				Manifest: manifest,
				Package:  pkg,
				Threat: &jsonreportspec.ReportThreat{
					Id: jsonreportspec.ReportThreat_LockfilePoisoning,
					InstanceId: ThreatInstanceId(jsonreportspec.ReportThreat_LockfilePoisoning,
						jsonreportspec.ReportThreat_Manifest,
						manifest.GetDisplayPath()),
					Message:     message,
					SubjectType: jsonreportspec.ReportThreat_Manifest,
					Subject:     manifest.GetDisplayPath(),
					Confidence:  jsonreportspec.ReportThreat_Medium,
					Source:      lfpThreatSource,
					SourceId:    lfpThreatSourceId,
				},
			})
		}

		if !npmIsUrlFollowsPathConvention(lockfilePackage.Resolved, packageName, trustedRegistryUrls, userTrustUrls) {
			logger.Debugf("npmLockfilePoisoningAnalyzer: Package [%s] resolved to an unconventional URL [%s]",
				packageName, lockfilePackage.Resolved)

			message := fmt.Sprintf("Package `%s` resolved to an URL `%s` that does not follow the "+
				"package name path convention", packageName, lockfilePackage.Resolved)

			_ = handler(&AnalyzerEvent{
				Source:   lfpAnalyzerName,
				Type:     ET_LockfilePoisoningSignal,
				Message:  message,
				Manifest: manifest,
				Package:  pkg,
				Threat: &jsonreportspec.ReportThreat{
					Id: jsonreportspec.ReportThreat_LockfilePoisoning,
					InstanceId: ThreatInstanceId(jsonreportspec.ReportThreat_LockfilePoisoning,
						jsonreportspec.ReportThreat_Manifest,
						manifest.GetDisplayPath()),
					Message:     message,
					SubjectType: jsonreportspec.ReportThreat_Manifest,
					Subject:     manifest.GetDisplayPath(),
					Confidence:  jsonreportspec.ReportThreat_Medium,
					Source:      lfpThreatSource,
					SourceId:    lfpThreatSourceId,
				},
			})
		}
	}

	return nil
}

// Analyze the artifact URL and determine if the source is trusted
func npmIsTrustedSource(sourceUrl string, trusteUrls []string) bool {
	parsedUrl, err := npmParseSourceUrl(sourceUrl)
	if err != nil {
		logger.Errorf("npmIsTrustedSource: Failed to parse URL %s: %v",
			sourceUrl, err)
		return false
	}

	scheme := parsedUrl.Scheme
	host := parsedUrl.Hostname()
	port := parsedUrl.Port()
	path := parsedUrl.Path

	// Always true for local filesystem URLs
	if scheme == "file" || scheme == "" {
		return true
	}

	// Compare with trusted URLs
	for _, trusteUrl := range trusteUrls {
		parsedTrustedUrl, err := npmParseSourceUrl(trusteUrl)
		if err != nil {
			logger.Errorf("npmIsTrustedSource: Failed to parse trusted URL %s: %v",
				trusteUrl, err)
			continue
		}

		if parsedTrustedUrl.Scheme != "" && parsedTrustedUrl.Scheme != scheme {
			continue
		}

		if !strings.EqualFold(parsedTrustedUrl.Host, host) {
			continue
		}

		if parsedTrustedUrl.Port() != "" && parsedTrustedUrl.Port() != port {
			continue
		}

		if parsedTrustedUrl.Path != "" && !strings.HasPrefix(path, parsedTrustedUrl.Path) {
			continue
		}

		return true
	}

	return false
}

func npmParseSourceUrl(sourceUrl string) (*url.URL, error) {
	// Go url parser cannot handle git+ssh://host:project/repo.git#commit
	if len(sourceUrl) > 10 && strings.EqualFold(sourceUrl[0:10], "git+ssh://") {
		if cIndex := strings.Index(sourceUrl[10:], ":"); cIndex != -1 {
			sourceUrl = sourceUrl[0:10+cIndex] + "/" + sourceUrl[10+cIndex+1:]
		}
	}

	return url.Parse(sourceUrl)
}

// Extract the package name from the node_modules filesystem path
func npmNodeModulesPackagePathToName(path string) string {
	return utils.NpmNodeModulesPackagePathToName(path)
}

// Test if URL follows the pkg name path convention as per NPM package registry
// specification https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
func npmIsUrlFollowsPathConvention(sourceUrl string, pkg string, trustedUrls []string, userTrustedUrls []string) bool {
	// Parse the source URL
	parsedUrl, err := npmParseSourceUrl(sourceUrl)
	if err != nil {
		logger.Errorf("npmIsUrlFollowsPathConvention: Failed to parse URL %s: %v", sourceUrl, err)
		return false
	}

	path := parsedUrl.Path
	if path == "" {
		return false
	}

	if path[0] == '/' {
		path = path[1:]
	}

	// Build a list of acceptable package names
	acceptablePackageNames := []string{pkg}
	for _, trustedUrl := range trustedUrls {
		parsedTrustedUrl, err := npmParseSourceUrl(trustedUrl)
		if err != nil {
			logger.Errorf("npmIsUrlFollowsPathConvention: Failed to parse trusted URL %s: %v", trustedUrl, err)
			continue
		}

		trustedBase := strings.Trim(parsedTrustedUrl.Path, "/")
		acceptablePackageNames = append(acceptablePackageNames, fmt.Sprintf("%s/%s", trustedBase, pkg))
	}

	// Extract the scoped package name
	scopedPackageName := strings.Split(path, "/-/")[0]
	if slices.Contains(acceptablePackageNames, scopedPackageName) {
		return true
	}

	// Check if the source URL starts with any trusted URL except the NPM trusted base URL
	for _, trustedUrl := range userTrustedUrls {
		if strings.HasPrefix(sourceUrl, trustedUrl) {
			return true
		}
	}

	// Default fallback
	return false
}
