package reporter

// Dependency Track integration for vet. The goal is to have `vet` seamlessly
// sync data into Dependency Track (DT) so that DT can be used as a single source
// of truth for managing OSS components inventory.
//
// We will use DTrack's `v1/bom` API to sync data from `vet` to DT. The `v1/bom`
// seems to be suitable because DTrack will internally create the project and update
// the components as required. Also it allows us to build an interim feature i.e. ability
// to generate CycloneDX BOM from `vet` as an independent feature.

// Define an interface that will be used by DTrack reporter to discover project
// information from `vet` runtime.
type DTrackProjectDiscoveryService interface {
	GetProjectName() string
	GetProjectVersion() string
}

// Define configuration for DTrack reporter
type DTrackReporterConfig struct {
	ApiKey     string
	ApiBaseUrl string
}

// The internal state for DTrack reporter
type dtrackReporter struct {
	config *DTrackReporterConfig
}

// Build a new DTrack reporter using the provided configuration
func NewDTrackReporter(config *DTrackReporterConfig) (*dtrackReporter, error) {
	return &dtrackReporter{config: config}, nil
}
