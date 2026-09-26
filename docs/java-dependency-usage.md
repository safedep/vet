# Java dependency usage evidence

`vet code scan` records Java imports and references in a code database. Run
`vet scan --code` with that database to attach usage evidence to Maven
dependencies from `pom.xml`, a lockfile, or a CycloneDX SBOM:

```sh
vet code scan --app src --db code.db --lang java
vet scan -D . --code code.db
```

Java import names do not reliably encode Maven coordinates. For example,
`org.apache.commons.lang3.StringUtils` belongs to
`org.apache.commons:commons-lang3`. Vet therefore checks whether each imported
class exists in the dependency's locally cached JAR before attaching the
evidence. It checks the default Maven cache (`~/.m2/repository`) and Gradle
cache (`~/.gradle/caches/modules-2/files-2.1`). Set `MAVEN_REPO_LOCAL` or
`GRADLE_USER_HOME` when those caches are elsewhere.

The scan does not download JARs. An uncached artifact cannot be matched, so
its usage remains unknown. Resolve the project's dependencies with Maven or
Gradle before scanning if you want Java usage evidence. Vet also supports
static member and wildcard imports when the corresponding class or package
is present in the JAR.
