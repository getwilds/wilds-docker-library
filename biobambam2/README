# biobambam2

This directory contains Docker images for biobambam2, a collection of tools for processing BAM files with a focus on name collation, sorting, duplicate marking, and alignment filtering.

## Available Versions

- `latest`: The most up-to-date stable version (currently biobambam2 v2.0.185)
- `2.0.185`: biobambam2 v2.0.185

## Image Details

These Docker images are built from Ubuntu Noble (24.04) and include:

- biobambam2 v2.0.185: A suite of tools for processing BAM files with C++ implementations for improved performance

The images are designed to be minimal and focused on a specific version of biobambam2 with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/biobambam2:latest
# or
docker pull getwilds/biobambam2:2.0.185

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/biobambam2:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/biobambam2:latest
# or
apptainer pull docker://getwilds/biobambam2:2.0.185

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/biobambam2:latest
```

### Example Commands

```bash
# Mark duplicates in a BAM file
docker run --rm -v /path/to/data:/data getwilds/biobambam2:latest bammarkduplicates I=/data/input.bam O=/data/marked.bam M=/data/metrics.txt

# Convert BAM to FastQ
docker run --rm -v /path/to/data:/data getwilds/biobambam2:latest bamtofastq I=/data/input.bam F=/data/output_1.fq F2=/data/output_2.fq
```

## Security Features

The biobambam2 Docker images include:

- Installation through Ubuntu package repositories for properly vetted binaries
- Pinned versions for reproducibility
- Minimal installation with only required dependencies

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs.txt` file in this directory, which is automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu Noble (24.04) as the base image
2. Adds metadata labels for documentation and attribution
3. Installs biobambam2 directly from the Ubuntu package repository with version pinning
4. Cleans up package caches to minimize image size

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
