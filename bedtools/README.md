# BEDTools

This directory contains Docker images for BEDTools, a powerful toolset for genome arithmetic with BED files and other genomic data formats.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bedtools/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/bedtools/CVEs_latest.md) )
- `2.31.1` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bedtools/Dockerfile_2.31.1) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/bedtools/CVEs_2.31.1.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- BEDTools v2.31.1: A suite of utilities for genomic feature operations and manipulations

The images are designed to be minimal and focused on a specific version of BEDTools with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/bedtools:latest
# or
docker pull getwilds/bedtools:2.31.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/bedtools:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/bedtools:latest
# or
apptainer pull docker://getwilds/bedtools:2.31.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/bedtools:latest
```

### Example Commands

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/bedtools:latest bedtools intersect -a file1.bed -b file2.bed > intersections.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bedtools:latest bedtools intersect -a file1.bed -b file2.bed > intersections.bed

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data bedtools_latest.sif bedtools intersect -a file1.bed -b file2.bed > intersections.bed
```

## Security Features

The BEDTools Docker images include:

- Dynamic versioning for build-essential to ensure the latest security patches
- Installation through Ubuntu package repositories for properly vetted binaries
- Minimal installation with only required dependencies

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/bedtools), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Dynamically determines and pins the latest security-patched version of build-essential
4. Installs BEDTools directly from the Ubuntu package repository
5. Cleans up package caches to minimize image size

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
