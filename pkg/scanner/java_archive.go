package scanner

import (
	"archive/zip"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/safedep/vet/ent"
)

// javaArchiveIndex contains class names from one resolved Maven artifact. The
// archive's directory, rather than its filename, supplies the coordinates.
type javaArchiveIndex struct {
	classes  map[string]struct{}
	packages map[string]struct{}
}

func indexJavaArchive(archivePath string) (*javaArchiveIndex, error) {
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, err
	}
	defer archive.Close()

	index := &javaArchiveIndex{
		classes:  make(map[string]struct{}),
		packages: make(map[string]struct{}),
	}
	for _, file := range archive.File {
		if !strings.HasSuffix(file.Name, ".class") || strings.HasPrefix(file.Name, "META-INF/") {
			continue
		}
		if base := path.Base(file.Name); base == "package-info.class" || base == "module-info.class" {
			continue
		}
		class := strings.TrimSuffix(file.Name, ".class")
		index.classes[class] = struct{}{}
		// Java imports spell nested classes with dots, while JAR entries use '$'.
		if strings.Contains(class, "$") {
			index.classes[strings.ReplaceAll(class, "$", "/")] = struct{}{}
		}
		if slash := strings.LastIndexByte(class, '/'); slash > 0 {
			index.packages[class[:slash]] = struct{}{}
		}
	}
	return index, nil
}

// containsJavaImport accepts a class import, a static member import, or a
// wildcard package import. Java nested classes use '$' in archive filenames.
func (index *javaArchiveIndex) containsJavaImport(evidence *ent.DepsUsageEvidence) bool {
	if evidence == nil || !strings.HasSuffix(strings.ToLower(evidence.UsageFilePath), ".java") {
		return false
	}
	module := strings.ReplaceAll(evidence.ModuleName, ".", "/")
	if evidence.IsWildCardUsage {
		if _, ok := index.packages[module]; ok {
			return true
		}
	}
	for module != "" {
		if _, ok := index.classes[module]; ok {
			return true
		}
		lastSlash := strings.LastIndexByte(module, '/')
		if lastSlash < 0 {
			break
		}
		// A trailing identifier may be a static member or nested class.
		module = module[:lastSlash]
	}
	return false
}

// localJavaArchives locates already downloaded Maven and Gradle artifacts.
// No package downloads are performed during enrichment.
func localJavaArchives(group, artifact, version string) []string {
	if !safeMavenCoordinate(group, artifact, version) {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	mavenRoot := os.Getenv("MAVEN_REPO_LOCAL")
	if mavenRoot == "" {
		mavenRoot = filepath.Join(home, ".m2", "repository")
	}
	gradleRoot := os.Getenv("GRADLE_USER_HOME")
	if gradleRoot == "" {
		gradleRoot = filepath.Join(home, ".gradle")
	}

	paths := []string{}
	mavenPath := filepath.Join(mavenRoot, filepath.FromSlash(strings.ReplaceAll(group, ".", "/")), artifact, version, artifact+"-"+version+".jar")
	if _, err := os.Stat(mavenPath); err == nil {
		paths = append(paths, mavenPath)
	}
	gradlePattern := filepath.Join(gradleRoot, "caches", "modules-2", "files-2.1", group, artifact, version, "*", artifact+"-"+version+".jar")
	gradlePaths, _ := filepath.Glob(gradlePattern)
	return append(paths, gradlePaths...)
}

func safeMavenCoordinate(parts ...string) bool {
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, `/\:*?[]"<>|`) || strings.Contains(part, "..") {
			return false
		}
	}
	return true
}
