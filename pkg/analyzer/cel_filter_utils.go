package analyzer

import (
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/text"
)

type celFilterStat struct {
	evaluatedManifests int
	evaluatedPackages  int
	matchedPackages    int
	errCount           int
}

func (s *celFilterStat) IncScannedManifest() {
	s.evaluatedManifests += 1
}

func (s *celFilterStat) IncEvaluatedPackage() {
	s.evaluatedPackages += 1
}

func (s *celFilterStat) IncMatchedPackage() {
	s.matchedPackages += 1
}

func (s *celFilterStat) IncError(_ error) {
	s.errCount += 1
}

func (s *celFilterStat) EvaluatedManifests() int {
	return s.evaluatedManifests
}

func (s *celFilterStat) EvaluatedPackages() int {
	return s.evaluatedPackages
}

func (s *celFilterStat) MatchedPackages() int {
	return s.matchedPackages
}

func (s *celFilterStat) ErrorCount() int {
	return s.errCount
}

func (s *celFilterStat) PrintStatMessage(writer io.Writer) {
	fmt.Fprintf(writer, "%s\n", text.Bold.Sprint("Filter evaluated with ",
		s.matchedPackages, " out of ", s.evaluatedPackages, " uniquely matched and ",
		s.errCount, " error(s) ", "across ", s.evaluatedManifests,
		" manifest(s)"))

}
