package exceptions

import (
	"io"
	"os"
	"sync"
	"time"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/exceptionsapi"
)

type exceptionsFileLoader struct {
	m     sync.Mutex
	idx   int
	suite *exceptionsapi.ExceptionSuite
}

func NewExceptionsFileLoader(path string) (exceptionsLoader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return newExceptionsFileLoaderUsingReader(file)
}

func newExceptionsFileLoaderUsingReader(reader io.Reader) (exceptionsLoader, error) {
	var suite exceptionsapi.ExceptionSuite
	err := utils.FromYamlToPb(reader, &suite)
	if err != nil {
		return nil, err
	}

	return &exceptionsFileLoader{
		suite: &suite,
	}, nil
}

func (f *exceptionsFileLoader) Read() (*exceptionRule, error) {
	f.m.Lock()
	defer f.m.Unlock()

	if f.idx >= len(f.suite.Exceptions) {
		return nil, io.EOF
	}

	cx := f.suite.Exceptions[f.idx]
	f.idx += 1

	expiry, err := time.Parse(time.RFC3339, cx.Expires)
	if err != nil {
		return nil, err
	}

	return &exceptionRule{
		spec:   cx,
		expiry: expiry,
	}, nil
}
