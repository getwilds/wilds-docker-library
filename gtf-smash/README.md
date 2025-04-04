# gtf-smash

This directory contains Docker images for gtf-smash, a toolkit for processing and collapsing GTF annotation files, primarily for use with RNA-SeQC and other RNA-seq analysis tools.

## Available Versions

- `latest`: The most up-to-date stable version using the master branch
- `v8`: Version corresponding to GTEx v8 pipeline

## Image Details

These Docker images are built from Python 3.12-slim and include:

- collapse_annotation.py: A Python script for collapsing GTF annotation files
- pandas: For data manipulation
- bx-python: For interval operations on genomic datasets

The images are designed to provide a lightweight environment for GTF file processing, particularly in RNA-seq analysis pipelines.

## Usage

### Docker

```bash
docker pull getwilds/gtf-smash:latest
# or
docker pull getwilds/gtf-smash:v8

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/gtf-smash:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/gtf-smash:latest
# or
apptainer pull docker://getwilds/gtf-smash:v8

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/gtf-smash:latest
```

### Example Command

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/gtf-smash:latest collapse_annotation.py --gtf /data/input.gtf --out /data/collapsed.gtf

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/gtf-smash:latest collapse_annotation.py --gtf /data/input.gtf --out /data/collapsed.gtf

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data gtf-smash_latest.sif collapse_annotation.py --gtf /data/input.gtf --out /data/collapsed.gtf
```

## Security Features

The gtf-smash Docker images include:

- Python 3.12 slim base image for minimal attack surface
- Pinned versions for all dependencies to ensure reproducibility
- Minimal installation with only required packages
- Explicit permission setting for executable scripts

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in this directory, which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Python 3.12-slim as the base image
2. Adds metadata labels for documentation and attribution
3. Installs wget for downloading scripts
4. Downloads the collapse_annotation.py script from the Broad Institute's GTEx pipeline repository
5. Makes the script executable and adds it to PATH
6. Installs required Python packages with pinned versions
7. Cleans up installation files to minimize image size

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
