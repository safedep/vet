package scanner

// Implement hooks for various callbacks during scanning
const (
	scanHookInit                   = 0
	scanHookBeforeEnrichManifest   = 1
	scanHookAfterEnrichManifest    = 2
	scanHookBeforeAnalyzeManifest  = 3
	scanHookAfterAnalyzeManifest   = 4
	scanHookBeforePolicyEvaluation = 5
	scanHookAfterPolicyEvaluation  = 6
	scanHookBeforeFinish           = 10
)
