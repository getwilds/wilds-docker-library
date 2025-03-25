# BWA

This directory contains Docker images for the Burrows-Wheeler Aligner (BWA), a software package for mapping low-divergent sequences against a large reference genome.

## Available Versions

- `latest`: The most up-to-date stable version (currently BWA v0.7.17 with Samtools v1.11)
- `0.7.17`: BWA v0.7.17 with Samtools v1.11

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- BWA v0.7.17: A software package for mapping DNA sequences against a reference genome
- Samtools v1.11: A suite of programs for interacting with high-throughput sequencing data

The images are designed to be minimal and focused on a specific version of BWA with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/bwa:latest
# or
docker pull getwilds/bwa:0.7.17

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/bwa:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/bwa:latest
# or
apptainer pull docker://getwilds/bwa:0.7.17

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/bwa:latest
```

### Example Command

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/bwa:latest bwa mem -t 4 reference.fa reads_1.fq reads_2.fq > aligned_reads.sam

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bwa:latest bwa mem -t 4 reference.fa reads_1.fq reads_2.fq > aligned_reads.sam

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data bwa_latest.sif bwa mem -t 4 reference.fa reads_1.fq reads_2.fq > aligned_reads.sam
```

## Security Features

The BWA Docker images include:

- Dynamic versioning for all dependencies to ensure the latest security patches
- Pinned versions for reproducibility
- Minimal installation with only required dependencies
- Health check to verify the BWA installation

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs.txt` file in this directory, which is automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Dynamically determines and pins the latest security-patched versions of dependencies
4. Downloads and builds BWA v0.7.17 from source
5. Includes Samtools v1.11 built from source
6. Sets up a working directory at `/data` for workflow execution
7. Implements a health check to verify the BWA installation

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
