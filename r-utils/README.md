# r-utils

This directory contains Docker images for r-utils, a general-purpose R environment built on Rocker/tidyverse with additional commonly used CRAN packages.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/r-utils/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/r-utils/CVEs_latest.md) )
- `0.1.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/r-utils/Dockerfile_0.1.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/r-utils/CVEs_0.1.0.md) )

## Image Details

These Docker images are built from the Rocker/tidyverse:4 base image and include:

- Tidyverse R packages: A collection of R packages for data science and analysis
- optparse: For command-line argument parsing in R scripts
- lubridate: For date-time manipulation

The images are designed to provide a general-purpose R environment suitable for WILDS WDL modules that need tidyverse plus common utility packages.

## Usage

### Docker

```bash
docker pull getwilds/r-utils:latest
# or
docker pull getwilds/r-utils:0.1.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/r-utils:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/r-utils:latest
# or
apptainer pull docker://getwilds/r-utils:0.1.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/r-utils:latest
```

### Example Commands

```bash
# Run an R script with Docker
docker run --rm -v /path/to/data:/data getwilds/r-utils:latest \
  Rscript /data/analysis.R --input /data/input.csv --output /data/results.csv

# Run an R script with Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/r-utils:latest \
  Rscript /data/analysis.R --input /data/input.csv --output /data/results.csv

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data r-utils_latest.sif \
  Rscript /data/analysis.R --input /data/input.csv --output /data/results.csv
```

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/r-utils), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Rocker/tidyverse:4 as the base image, which provides R 4.x with tidyverse packages
2. Adds metadata labels for documentation and attribution
3. Sets R library paths to avoid host contamination in Apptainer
4. Installs additional R packages (optparse, lubridate)
5. Sets up a working directory for data analysis
6. Runs a smoke test to verify package installation

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
