package scanner

// Implement hooks for various callbacks during scanning

const (
	ScanHookInit                   = 0
	ScanHookBeforeEnrichManifest   = 1
	ScanHookAfterEnrichManifest    = 2
	ScanHookBeforeAnalyzeManifest  = 3
	ScanHookAfterAnalyzeManifest   = 4
	ScanHookBeforePolicyEvaluation = 5
	ScanHookAfterPolicyEvaluation  = 6
	ScanHookBeforeFinish           = 10
)
