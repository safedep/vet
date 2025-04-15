package utils

import "github.com/google/osv-scanner/pkg/lockfile"

func GetLanguageFromOsvEcosystem(ecosystem lockfile.Ecosystem) (string, bool) {
	switch ecosystem {
	case lockfile.NpmEcosystem:
		return "JavaScript", true
	case lockfile.NuGetEcosystem:
		return "C#", true
	case lockfile.CargoEcosystem:
		return "Rust", true
	case lockfile.BundlerEcosystem:
		return "Ruby", true
	case lockfile.ComposerEcosystem:
		return "PHP", true
	case lockfile.GoEcosystem:
		return "Go", true
	case lockfile.MixEcosystem:
		return "Elixir", true
	case lockfile.MavenEcosystem:
		return "Java", true
	case lockfile.PipEcosystem:
		return "Python", true
	case lockfile.PubEcosystem:
		return "Dart", true
	case lockfile.ConanEcosystem:
		return "C/C++", true
	case lockfile.CRANEcosystem:
		return "Rust", true
	}

	return "", false
}
