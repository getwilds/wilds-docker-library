# HADES

This directory contains a Docker image for [HADES](https://ohdsi.github.io/Hades/) (Health Analytics Data-to-Evidence Suite), the OHDSI collection of R packages for large-scale observational health data analysis on the OMOP Common Data Model.

The image is built on top of the Databricks R cluster runtime (`databricksruntime/rbase`) so it can run as Databricks cluster compute, with HADES installed on top of the base image's own R installation. HADES is restored from a pinned `renv.lock` rather than installed live, so its dependency versions are reproducible and the build doesn't depend on GitHub API rate limits at build time.

A separate `full` tag is also published, built from `Dockerfile_full`: a Databricks-parity image that matches the exact Posit Package Manager mirror and from-source R build used in production Databricks clusters. It is kept available (with its own `renv-full.lock`) while the simplified `latest`/`1.20.0` build above is evaluated as a lighter-weight replacement.

## Available Versions

- `latest`: HADES 1.20.0 on `databricksruntime/rbase:17.3-LTS`
- `1.20.0`: HADES 1.20.0 on `databricksruntime/rbase:17.3-LTS`
- `full`: Databricks-parity HADES 2026Q1 build (see [Dockerfile_full](Dockerfile_full))

## Image Size

This image is large (~5-6GB) because HADES's own dependency tree (over 200 R packages, including heavyweight compiled packages like `duckdb`) is compiled from source rather than installed from a binary package mirror. This is inherent to HADES itself, not something trimmed further without dropping functionality.

## Platform Availability

**Note:** This image is built for **linux/amd64** only, to match Databricks cluster compute.

## Building

Run from the repository root, since each Dockerfile's `COPY renv.lock` is rooted there:

```bash
docker buildx build --platform linux/amd64 -t getwilds/hades:latest \
  -f hades/Dockerfile_latest .
```

**Note:** `make build_amd64 IMAGE=hades` (and `make build`/`make validate`) will not work for this tool, since the Makefile builds every tool with that tool's own subdirectory as context, while this Dockerfile expects repo-root context to resolve its `COPY` path. Use the `docker buildx build` command above instead.

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

## Installed Components

- [HADES](https://ohdsi.github.io/Hades/) 1.20.0, which in turn pulls in the full suite of OHDSI R packages (DatabaseConnector, SqlRender, CohortGenerator, FeatureExtraction, PatientLevelPrediction, and others)
- R, as shipped by the `databricksruntime/rbase:17.3-LTS` base image

## Security Features

- HADES and its full dependency tree are pinned via `renv.lock` for reproducibility
- Pinned versions for system dependencies via `apt-cache policy` to ensure reproducible, security-patched builds

### Security Scanning and CVEs

This image is regularly scanned for vulnerabilities using Docker Scout. However, due to the size and nature of the HADES dependency tree, it may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, this image is primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in this directory, which are automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Design Notes

- **Base image**: `databricksruntime/rbase`, not `databricksruntime/standard` (the latter is Python/Spark-only and has no R installed at all).
- **Pinned lockfile instead of a live install**: HADES pulls in 18 packages from `github.com/ohdsi`. Resolving their dependency graph live (`remotes::install_github()`) means recursively querying the GitHub API for every dependency-of-a-dependency, which burns through the unauthenticated 60-requests/hour limit before the install finishes. `renv::restore()` against a pre-resolved `renv.lock` only needs one API call per GitHub package (18 total), comfortably within that limit.
- **Raised `renv.install.timeout`**: `renv::restore()` applies one deadline to the whole restore (3600 seconds by default). Compiling ~210 packages from source (no binary package mirror is used here) comfortably overruns that default, so the build raises it to 21600 seconds (6 hours).
- **`transactional = FALSE`**: `renv`'s default transactional install stages every package in a temporary library and only migrates them into the real project library once the whole restore succeeds. A package installed mid-restore that runs its own dependency check (e.g. `OhdsiSharing` checking for `rJava`/`ParallelLogger`) looks at the not-yet-populated project library and fails even though its dependency already installed successfully. `transactional = FALSE` installs packages directly into the project library as they finish instead.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository. See [CONTRIBUTING.md](https://github.com/getwilds/wilds-docker-library/blob/main/CONTRIBUTING.md) for details on contributing new images or updates.
