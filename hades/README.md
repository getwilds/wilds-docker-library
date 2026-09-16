# HADES

This directory contains a Docker image for [HADES](https://ohdsi.github.io/Hades/) (Health Analytics Data-to-Evidence Suite), the OHDSI collection of R packages for large-scale observational health data analysis on the OMOP Common Data Model.

HADES is restored from a pinned lockfile (`renv_<hades-version>.lock`) rather than installed live, so its dependency versions are reproducible and the build doesn't depend on GitHub API rate limits at build time.

## Available Versions

- `latest`: HADES 1.20.0 on `rocker/r-ver:4.6.1`
- `1.20.0`: HADES 1.20.0 on `rocker/r-ver:4.6.1`
- `1.20.0dbx`: HADES 1.20.0 on `databricksruntime/rbase:17.3-LTS`

**Note:** unlike `latest`/`1.20.0`, which get overwritten in place on future HADES updates, the Databricks variant is versioned per-file (`Dockerfile_1.20.0dbx`, `Dockerfile_1.21.0dbx`, etc.) and prior versions are kept rather than replaced, so a given Databricks image tag stays pullable indefinitely.

## Image Size

This image is large (~5-6GB) because HADES's own dependency tree (over 200 R packages, including heavyweight compiled packages like `duckdb`) is compiled from source rather than installed from a binary package mirror. This is inherent to HADES itself, not something trimmed further without dropping functionality.

## Platform Availability

The `latest` and `1.20.0` Dockerfiles are capable of building for both `linux/amd64` and `linux/arm64`. However, the `1.20.0dbx` image is built from a Databricks Runtime base and is `linux/amd64` only (Databricks clusters are x86_64), and `amd64_only_tools.txt` applies per directory rather than per Dockerfile. So with `hades` listed there, CI currently builds and publishes **all** tags as `linux/amd64` only; ARM64 images are not published for this tool even though `latest`/`1.20.0` could support it.

## Building

Run from the repository root, since each Dockerfile's `COPY renv_<hades-version>.lock` is rooted there:

```bash
docker buildx build --platform linux/amd64 -t getwilds/hades:latest \
  -f hades/Dockerfile_latest .
```

**Note:** `make build_amd64 IMAGE=hades` (and `make build`/`make validate`) will not work for this tool, since the Makefile builds every tool with that tool's own subdirectory as context, while these Dockerfiles expect repo-root context to resolve their `COPY` path. Use the `docker buildx build` command above instead.

## Usage

### Docker

```bash
docker pull getwilds/hades:latest

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/hades:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/hades:latest

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/hades:latest
```

### Example Commands

```bash
# Launch an interactive R session with HADES loaded
docker run --rm -it -v /path/to/data:/data getwilds/hades:latest R

# Run an R script that uses HADES packages
docker run --rm -v /path/to/data:/data getwilds/hades:latest Rscript /data/my_analysis.R

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/hades:latest R
```

### Databricks (`1.20.0dbx` tag)

The `1.20.0dbx` image is built from `databricksruntime/rbase:17.3-LTS` so it can be used as a [Databricks Container Services](https://docs.databricks.com/aws/en/compute/custom-containers) cluster image, with HADES installed on top of the base image's own R installation.

Notes:

- The tag is pinned to both a HADES version and a specific Databricks Runtime version (`Dockerfile_<hades-version>dbx`). Match it to your cluster's DBR version; a mismatch between the container's R stack and the runtime host is unsupported by Databricks. Unlike `latest`/`1.20.0`, older `*dbx` Dockerfiles and tags are kept rather than overwritten when HADES updates, so pin to the specific version your cluster needs.
- This image only applies to **classic compute** with Container Services enabled. Serverless compute cannot use custom container images.
- HADES's `DatabaseConnector` package supports Spark/Databricks as one of many database backends (alongside Postgres, SQL Server, Oracle, Redshift, BigQuery, Snowflake, and others). The `latest`/`1.20.0` images are not Databricks-specific and can connect to any of these; use a `*dbx` tag specifically when you need the image to run *as* Databricks cluster compute itself.

## Installed Components

- [HADES](https://ohdsi.github.io/Hades/) 1.20.0, which in turn pulls in the full suite of OHDSI R packages (DatabaseConnector, SqlRender, CohortGenerator, FeatureExtraction, PatientLevelPrediction, and others)
- R 4.6.1, as shipped by the `rocker/r-ver:4.6.1` base image (`latest`/`1.20.0`) or `databricksruntime/rbase:17.3-LTS` (`1.20.0dbx`)

## Security Features

- HADES and its full dependency tree are pinned via a per-version `renv_<hades-version>.lock` for reproducibility
- Pinned versions for system dependencies via `apt-cache policy` to ensure reproducible, security-patched builds

### Security Scanning and CVEs

This image is regularly scanned for vulnerabilities using Docker Scout. However, due to the size and nature of the HADES dependency tree, it may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, this image is primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in this directory, which are automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Design Notes

- **Generic base for `latest`/`1.20.0`**: `rocker/r-ver:4.6.1`, not a Databricks base image. HADES is not Databricks-specific in practice: its core DB connectivity package, `DatabaseConnector`, supports Postgres, SQL Server, Oracle, Redshift, BigQuery, Snowflake, and Spark/Databricks (added later, for large-scale sites). The OHDSI community's standard onboarding path ([OHDSI/Broadsea](https://github.com/OHDSI/Broadsea)) runs HADES against local/generic Postgres. `rocker/r-ver:4.6.1` was chosen over plain `r-base` because it pins an explicit, reproducible R version rather than tracking a rolling Debian release, and it matches the Ubuntu 24.04 base and R 4.6.1 version already validated for the `1.20.0dbx` image, so the same lockfile content restores on both without regeneration.
- **`*dbx` base image**: `databricksruntime/rbase`, not `databricksruntime/standard` (the latter is Python/Spark-only and has no R installed at all).
- **`*dbx` files are versioned and kept, not overwritten**: `latest`/`1.20.0` are replaced in place on a HADES update, matching every other tool in this repo. The Databricks variant instead keeps every past `Dockerfile_<version>dbx` (and its published `<version>dbx` tag) around when a new one is added, so a cluster pinned to a specific DBR/HADES combination doesn't have its image silently replaced out from under it.
- **Lockfile is named by HADES version, not by tag**: `latest`, `1.20.0`, and `1.20.0dbx` all `COPY` the same `renv_1.20.0.lock` today. `latest` and `1.20.0` are supposed to always be identical and are updated together on every HADES bump, so sharing one file is safe (and avoids a redundant duplicate) for those two. `1.20.0dbx`, however, is a *kept* file (see above) that must never change once published; it shares `renv_1.20.0.lock` only because it currently targets the same HADES version as `latest`/`1.20.0`. **On the next HADES update, rename/add `renv_1.21.0.lock` and repoint `Dockerfile_latest`/`Dockerfile_1.21.0` at it, but leave `renv_1.20.0.lock` and `Dockerfile_1.20.0dbx` untouched** (a new `Dockerfile_1.21.0dbx`, if one is added, gets the new lockfile instead). Deleting or overwriting `renv_1.20.0.lock` while `Dockerfile_1.20.0dbx` still references it would silently change what that "frozen" image builds.
- **Explicit JDK on `latest`/`1.20.0`**: unlike the Databricks runtime base (which ships a Zulu JDK), `rocker/r-ver` ships no JDK at all, so `default-jdk-headless` is installed explicitly and `JAVA_HOME`/`R CMD javareconf` are pointed at it for `rJava` (a `DatabaseConnector` dependency for JDBC drivers).
- **Pinned lockfile instead of a live install**: HADES pulls in 18 packages from `github.com/ohdsi`. Resolving their dependency graph live (`remotes::install_github()`) means recursively querying the GitHub API for every dependency-of-a-dependency, which burns through the unauthenticated 60-requests/hour limit before the install finishes. `renv::restore()` against a pre-resolved `renv_<hades-version>.lock` only needs one API call per GitHub package (18 total), comfortably within that limit.
- **Raised `renv.install.timeout`**: `renv::restore()` applies one deadline to the whole restore (3600 seconds by default). Compiling ~210 packages from source (no binary package mirror is used here) comfortably overruns that default, so the build raises it to 21600 seconds (6 hours).
- **`transactional = FALSE`**: `renv`'s default transactional install stages every package in a temporary library and only migrates them into the real project library once the whole restore succeeds. A package installed mid-restore that runs its own dependency check (e.g. `OhdsiSharing` checking for `rJava`/`ParallelLogger`) looks at the not-yet-populated project library and fails even though its dependency already installed successfully. `transactional = FALSE` installs packages directly into the project library as they finish instead.
- **`RENV_CONFIG_INSTALL_JOBS=1`**: forces `renv::restore()` to install packages serially. Its default parallel installer can attempt a package before its own dependencies have finished installing, which surfaces as a spurious "dependencies not available" failure for an unrelated package partway through the restore. This trades some install speed for reliability.
- **If a lockfile needs regenerating**: a base image change that also changes the R version will hit a hard ABI break restoring the existing lockfile against a mismatched R (e.g. `R_NamespaceRegistry` was removed from R's own headers between 4.4 and 4.6). The lockfile must be regenerated against whatever R version that Dockerfile's base image actually ships, as a new `renv_<hades-version>.lock` (never edit `renv_1.20.0.lock` in place while `Dockerfile_1.20.0dbx` still depends on it, per above). Expect the same subset of from-source build issues to potentially recur: missing apt dev headers (surfaced one at a time historically: `libzstd-dev` for `rJava`, `libuv1-dev` for `fs`, and Ubuntu 24.04's rename of `libfreetype6-dev` to `libfreetype-dev`), and the `JAVA_HOME`/`javareconf`/timeout/transactional/serial-install settings above.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository. See [CONTRIBUTING.md](https://github.com/getwilds/wilds-docker-library/blob/main/CONTRIBUTING.md) for details on contributing new images or updates.
