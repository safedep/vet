package utils

import (
	"fmt"
	"github.com/safedep/vet/pkg/common/logger"
)

func LogAndError(err error, message string) error {
	errorMsg := fmt.Sprintf("%s: %s", message, err)
	logger.Errorf(errorMsg)
	return fmt.Errorf(errorMsg)
}
