# Install vet

vet v2 is in alpha. Each merge to the `v2` branch that changes more than docs publishes a
pre-release with the version `2.0.0-alpha.<UTC timestamp>`. vet v1 stays the latest release, so
the v1 install commands still install v1. Use one of these channels for vet v2.

Every channel ships a build with CGO, so the code usage analysis works.

## Homebrew

```bash
brew install --cask safedep/tap/vet@edge
```

The `vet@edge` cask conflicts with the `vet` cask of v1. Run `brew uninstall vet` first if you
have v1. `brew upgrade --cask vet@edge` installs the newest alpha build.

## mise

```bash
mise use -g 'github:safedep/vet[prerelease=true]@2'
```

mise skips a pre-release unless `prerelease=true` is set. `@2` keeps mise on vet v2, because
`latest` gives the newest release by date, and that can be a v1 release.

mise installs only the releases that are older than 24 hours. This is its `minimum_release_age`
setting. A new alpha build is available to mise one day after its release. To install the newest
alpha build now, add `--minimum-release-age 0s`:

```bash
mise use -g --minimum-release-age 0s 'github:safedep/vet[prerelease=true]@2'
```

`mise upgrade` installs the newest alpha build that is older than 24 hours.

## Go

```bash
go install github.com/safedep/vet/v2/cmd/vet@latest
```

`@latest` installs the newest alpha build, because the v2 module has no release yet. The code
usage analysis needs a C compiler, such as the Xcode Command Line Tools or `gcc`. With no C
compiler, Go builds vet with `CGO_ENABLED=0`, and a scan records a diagnostic and runs with no code
usage.

## Container image

```bash
docker run --rm -v "$PWD:/src" -w /src ghcr.io/safedep/vet:v2-latest scan
```

`v2-latest` is the newest alpha build. Each build also has the tag of its version, for example
`v2.0.0-alpha.20261004163722`. The `latest` tag is vet v1.

## Release binaries

Download the archive for your platform from a `v2.0.0-alpha` pre-release on the
[releases page](https://github.com/safedep/vet/releases). The page keeps the last 5 alpha builds.
Each pre-release has `checksums.txt` and a GitHub build attestation:

```bash
sha256sum --check --ignore-missing checksums.txt
gh attestation verify vet_Linux_x86_64.tar.gz --repo safedep/vet
```

## Check the install

```bash
vet version
vet doctor
```

`vet doctor` checks the state directory, the config, the credentials and the endpoints.
