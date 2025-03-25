# STAR

This directory contains Docker images for STAR (Spliced Transcripts Alignment to a Reference), an RNA-seq aligner designed for high performance and accuracy.

## Available Versions

- `latest`: The most up-to-date stable version (currently STAR v2.7.6a with Samtools v1.11)
- `2.7.6a`: STAR v2.7.6a with Samtools v1.11
- `2.7.4a`: STAR v2.7.4a with Samtools v1.11

## Image Details

These Docker images are built from Ubuntu Oracular and include:

- STAR: A fast RNA-seq read mapper with high accuracy and support for splice junctions
- Samtools v1.11: A suite of programs for interacting with high-throughput sequencing data

The images are designed to be minimal and focused on a specific version of STAR with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/star:latest
# or
docker pull getwilds/star:2.7.6a
# or
docker pull getwilds/star:2.7.4a

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/star:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/star:latest
# or
apptainer pull docker://getwilds/star:2.7.6a
# or
apptainer pull docker://getwilds/star:2.7.4a

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/star:latest
```

### Example Command

```bash
docker run --rm -v /path/to/data:/data getwilds/star:latest STAR --runThreadN 4 --genomeDir /data/genome --readFilesIn /data/reads_1.fq /data/reads_2.fq --outFileNamePrefix /data/output/
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu Oracular as the base image
2. Adds metadata labels for documentation and attribution
3. Installs prerequisites with pinned versions
4. Downloads and builds STAR from source
5. Includes Samtools v1.11 built from source
6. Performs cleanup to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs.txt` file in this directory, which is automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
