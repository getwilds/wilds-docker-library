# consensus

This directory contains Docker images for ConsensusVariants, an R-based toolkit for generating consensus variant calls from multiple variant callers in genomic data analysis.

## Available Versions

- `latest`: The most up-to-date stable version (currently ConsensusVariants v0.1.1)
- `0.1.1`: ConsensusVariants v0.1.1

## Image Details

These Docker images are built from the Rocker/tidyverse:3.6.0 base image and include:

- ConsensusVariants v0.1.1: An R script for generating consensus variant calls from multiple callers
- Tidyverse R packages: A collection of R packages for data science and analysis
- consensus-trio-unpaired.R: Script for processing unpaired variant data

The images are designed to provide a stable R environment with all necessary dependencies for running the ConsensusVariants scripts.

## Usage

### Docker

```bash
docker pull getwilds/consensus:latest
# or
docker pull getwilds/consensus:0.1.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/consensus:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/consensus:latest
# or
apptainer pull docker://getwilds/consensus:0.1.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/consensus:latest
```

### Example Command

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/consensus:latest Rscript /consensus-trio-unpaired.R --caller1_vcf /data/caller1.vcf --caller2_vcf /data/caller2.vcf --caller3_vcf /data/caller3.vcf --output_vcf /data/consensus.vcf

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/consensus:latest Rscript /consensus-trio-unpaired.R --caller1_vcf /data/caller1.vcf --caller2_vcf /data/caller2.vcf --caller3_vcf /data/caller3.vcf --output_vcf /data/consensus.vcf

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data consensus_latest.sif Rscript /consensus-trio-unpaired.R --caller1_vcf /data/caller1.vcf --caller2_vcf /data/caller2.vcf --caller3_vcf /data/caller3.vcf --output_vcf /data/consensus.vcf
```

## Security Features

The consensus Docker images include:

- Based on the stable Rocker/tidyverse R environment
- Version-specific checkout of the ConsensusVariants repository
- Minimal installation with only required dependencies

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs.txt` file in this directory, which is automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Rocker/tidyverse:3.6.0 as the base image, which provides R 3.6.0 with tidyverse packages
2. Adds metadata labels for documentation and attribution
3. Sets Git SSL verification to work in secure environments
4. Clones the ConsensusVariants repository at a specific version tag
5. Extracts the necessary R scripts for variant processing
6. Cleans up to minimize image size

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
