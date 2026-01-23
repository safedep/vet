package scanner

// SkillScannerCallbacks defines callback functions for skill scanner lifecycle events
// This allows decoupling the scanner from UI/progress tracking concerns
type SkillScannerCallbacks struct {
	OnStart        ScannerCallbackNoArgFn  // Scanner is starting
	OnStartEnrich  ScannerCallbackNoArgFn  // Beginning skill enrichment (malware analysis submission)
	OnDoneEnrich   ScannerCallbackNoArgFn  // Enrichment completed
	OnStartAnalyze ScannerCallbackNoArgFn  // Beginning malware analysis
	OnDoneAnalyze  ScannerCallbackNoArgFn  // Analysis completed
	OnStartReport  ScannerCallbackNoArgFn  // Beginning report generation
	OnDoneReport   ScannerCallbackNoArgFn  // Report generation completed
	OnStop         ScannerCallbackErrArgFn // Scanner is stopping (with optional error)
}
