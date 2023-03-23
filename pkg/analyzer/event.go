package analyzer

func (ev *AnalyzerEvent) IsFailOnError() bool {
	return ev.Type == ET_AnalyzerFailOnError
}

func (ev *AnalyzerEvent) IsFilterMatch() bool {
	return ev.Type == ET_FilterExpressionMatched
}
