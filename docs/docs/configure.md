---
sidebar_position: 4
title: 🧩 Configuration
draft: true
---

# 🧩 Configuring Vet

`vet` comes with super powers 🚀, this section will help you to understand and explore some of them so that you can take your open source security to next level 😎

## Scanning

### Scanning Directories

- If you wanted to scan the whole directory & automatically parse the dependencies/lockfile, you can use the `-D` or `--directory` flag.

```bash
vet scan -D your-code/directory/path/
```

:::info

If you do not specify any directory, by default it takes present working directory as the input.

:::

### Scanning Files

- If you wanted to scan the specific file `lockfile` you can use the `-L` or `--lockfiles` flag.

```bash
vet scan -D your-code/directory/path/
```

:::info

If you do not specify any directory, by default it takes present working directory as the input.

:::

### Scanning Non-standard files

- Sometimes you might have non-standard filenames for the dependencies, lockfiles. You can scan them as a supported package manifest with a non-standard name using the following command

```bash
vet scan --lockfiles /path/to/gradle-compileOnly.lock --lockfile-as gradle.lockfile
```

### Scanning Multiple files

```bash
vet scan --lockfiles /path/to/gradle.lockfile --lockfiles requirements.txt
```

![vet scanning multiple files](/img/vet/scanning-multiple-files.png)

### Scanning Parsers

`vet` currently has 10 scanning parsers for various dependencies formats including Go, Python, Java, etc.

```bash
❯ vet scan parsers
Available Lockfile Parsers
==========================

[0] buildscript-gradle.lockfile
[1] go.mod
[2] gradle.lockfile
[3] package-lock.json
[4] Pipfile.lock
[5] pnpm-lock.yaml
[6] poetry.lock
[7] pom.xml
[8] requirements.txt
[9] yarn.lock
```

## Scan Options

### Silent scan

- `vet` supports silent scan to prevent rendering UI using the following command with `-s` or `--silent` flag

```bash
vet scan -s --lockfiles demo-client-java/gradle.lockfile
```

![vet silent scan](/img/vet/silent-scan.png)

### Scan concurrency

- By default it set to `5`, you can increase or decrease using the `--concurrency` or `-C` flag

```bash
 ❯ vet scan -C 10 --lockfiles demo-client-java/gradle.lockfile
Scanning packages    ... done! [115 in 5.87s]
Scanning manifests   ... done! [1 in 5.87s]
```

- You can see the difference between the above and below scan time with same file(s)

```bash
❯ vet scan -C 1 --lockfiles demo-client-java/gradle.lockfile
Scanning packages    ... done! [115 in 10.567s]
Scanning manifests   ... done! [1 in 10.567s]
```

### Scanning transitive dependencies

- You can perform the transitive dependencies scan by running the following command with `--transitive` flag

```bash
vet scan --transitive --lockfiles demo-client-java/gradle.lockfile
```

![vet transitive scan default](/img/vet/vet-transitive-default.png)

- As you can see the above scan has found issues across `201` libraries

### Configuring transitive dependencies depth level

- You can change the transitive dependencies scan depth by running the following command with `--transitive-depth` flag

```bash
vet scan --transitive --transitive-depth 5 --lockfiles demo-client-java/gradle.lockfile
```

![vet transitive scan depth](/img/vet/vet-transitive-depth.png)

- As you can see the above scan has found issues across `237` libraries

:::info

By default if you don't specify the flag it takes `2` as depth

:::
