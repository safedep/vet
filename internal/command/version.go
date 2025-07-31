package command

var globalVersion string

func SetVersion(version string) {
	globalVersion = version
}

func GetVersion() string {
	return globalVersion
}
