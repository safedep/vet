package utils

import (
	"fmt"
	"github.com/safedep/vet/pkg/common/logger"
)

func LogAndError(err error, message string) error {
	errMsg := message
	if err != nil {
		errMsg += fmt.Sprintf(": %s", err)
	}
	logger.Errorf(errMsg)
	return fmt.Errorf(errMsg)
}
