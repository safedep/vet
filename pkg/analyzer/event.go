package analyzer

func (ev *AnalyzerEvent) IsFailOnError() bool {
	return ev.Type == ET_AnalyzerFailOnError
}
