package utils

import (
	"fmt"
	"github.com/safedep/vet/pkg/common/logger"
)

func LogAndError(err error, message string) error {
	if err != nil {
		logger.Errorf("%s: %v", message, err)
		return fmt.Errorf("%s: %w", message, err)
	}
	logger.Errorf("%s", message)
	return fmt.Errorf("%s", message)
}
