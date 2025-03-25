# Samtools

This directory contains Docker images for Samtools, a suite of programs for interacting with high-throughput sequencing data.

## Available Versions

- `latest`: The most up-to-date stable version (currently Samtools v1.11)
- `1.11`: Samtools v1.11
- `1.10`: Samtools v1.10

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- Samtools: A suite of utilities for manipulating alignments in the SAM/BAM format
- Bedtools: A powerful toolset for genome arithmetic

The images are designed to be minimal and focused on a specific version of Samtools with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/samtools:latest
# or
docker pull getwilds/samtools:1.11
# or
docker pull getwilds/samtools:1.10

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/samtools:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/samtools:latest
# or
apptainer pull docker://getwilds/samtools:1.11
# or
apptainer pull docker://getwilds/samtools:1.10

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/samtools:latest
```

### Example Commands

```bash
# Convert SAM to BAM
docker run --rm -v /path/to/data:/data getwilds/samtools:latest samtools view -bS /data/input.sam > /data/output.bam

# Sort BAM file
docker run --rm -v /path/to/data:/data getwilds/samtools:latest samtools sort /data/input.bam -o /data/sorted.bam

# Index BAM file
docker run --rm -v /path/to/data:/data getwilds/samtools:latest samtools index /data/sorted.bam
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Dynamically determines and pins the latest security-patched versions of dependencies
4. Downloads and builds Samtools from source
5. Includes Bedtools for additional functionality
6. Performs cleanup to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs.txt` file in this directory, which is automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
