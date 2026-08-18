# HADES

This directory contains Docker images for [HADES](https://ohdsi.github.io/Hades/) (Health Analytics Data-to-Evidence Suite), the OHDSI collection of R packages for large-scale observational health data analysis on the OMOP Common Data Model.

Two variants are provided, both built from the same pinned HADES 2026Q1 lockfile (`renv.lock`, 294 packages including 16 pulled from `github.com/ohdsi`):

- **`latest`**: A lightweight build on a standard R base image, without Databricks-specific components. Recommended for local development and general HADES analyses.
- **`full`**: A full-parity build on the same Databricks Runtime 17.3 LTS and Posit Package Manager mirror used in production Databricks clusters. Use this variant when you need the container's environment to match a specific Databricks cluster.

## Available Versions

- `latest`: Lightweight HADES 2026Q1 build (R 4.4.1, `rocker/r-ver` base)
- `full`: Databricks-parity HADES 2026Q1 build (R 4.4.1, `databricksruntime/standard:17.3-LTS` base)

## Platform Availability

**Note:** These images are built for **linux/amd64** only. Several HADES dependencies (e.g. `duckdb`, `Cyclops`) are compiled from source during the `renv` restore, and the R 4.4.1 build in the `full` variant is not validated under QEMU emulation.

## Building

Run from the repository root, since each Dockerfile's `COPY` sources (`renv.lock`, `install-hades.R`, `validate-ohdsi.R`, `Rprofile.site`) are rooted there, matching how `docker_update.py` builds and publishes these images in CI:

```bash
# Lightweight build
docker buildx build --platform linux/amd64 -t getwilds/hades:latest \
  -f hades/Dockerfile_latest .

# Databricks-parity build
docker buildx build --platform linux/amd64 -t getwilds/hades:full \
  -f hades/Dockerfile_full .
```

**Note:** `make build_amd64 IMAGE=hades` (and `make build`/`make validate`) will *not* work for this tool, since the Makefile builds every tool with that tool's own subdirectory as context (`docker build ... hades/`), while these Dockerfiles expect repo-root context to resolve their `COPY` paths. Use the `docker buildx build` commands above for local builds instead.

## Usage

### Docker

```bash
docker pull getwilds/hades:latest
# or
docker pull getwilds/hades:full

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

Both images restore the full HADES 2026Q1 lockfile, including:

- **Foundations**: DatabaseConnector, SqlRender, ParallelLogger, Andromeda, Cyclops, duckdb, V8, CirceR, Eunomia
- **Analytics**: Achilles, DataQualityDashboard, CohortGenerator, CohortDiagnostics, FeatureExtraction, PatientLevelPrediction, CohortMethod, SelfControlledCaseSeries, Characterization, ResultModelManager
- **GitHub-only OHDSI packages**: Capr, Strategus, Hades, CohortExplorer, CohortIncidence, DeepPatientLevelPrediction, EnsemblePatientLevelPrediction, Keeper, MethodEvaluation, OhdsiSharing, OhdsiShinyModules, PhenotypeLibrary, PheValuator, ROhdsiWebApi, SelfControlledCohort

The `full` variant additionally includes Databricks notebook integration (Rserve, hwriterPlus) and compiles R 4.4.1 from source to match the Databricks Runtime environment exactly.

## Security Features

- Pinned R version (4.4.1) and pinned package versions via `renv.lock` for reproducibility
- Dynamic versioning for system dependencies (`latest` variant) to ensure the latest security patches

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the size and nature of the HADES dependency tree, some images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about these images, please check the `CVEs_*.md` files in this directory, which are automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository. See [CONTRIBUTING.md](https://github.com/getwilds/wilds-docker-library/blob/main/CONTRIBUTING.md) for details on contributing new images or updates.
