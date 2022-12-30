package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

func init() {
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)
}

func SetLogLevel(verbose, debug bool) {
	if verbose {
		logrus.SetLevel(logrus.InfoLevel)
	}

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.SetReportCaller(true)
	}
}

func Infof(msg string, args ...any) {
	logrus.Infof(msg, args...)
}

func Errorf(msg string, args ...any) {
	logrus.Errorf(msg, args...)
}

func Warnf(msg string, args ...any) {
	logrus.Warnf(msg, args...)
}

func Debugf(msg string, args ...any) {
	logrus.Debugf(msg, args...)
}

func LoggerWith(key string, value any) *logrus.Entry {
	return logrus.WithFields(logrus.Fields{
		key: value,
	})
}

func LoggerWithError(err error) *logrus.Entry {
	return LoggerWith("error", err.Error())
}
