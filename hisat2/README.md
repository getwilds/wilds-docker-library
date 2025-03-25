# hisat2

This directory contains Docker images for HISAT2, a fast and sensitive alignment program for mapping NGS reads to a population of genomes.

## Available Versions

- `latest`: The most up-to-date stable version (currently HISAT2 v2.2.1)
- `2.2.1`: HISAT2 v2.2.1

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- HISAT2 v2.2.1: A graph-based alignment tool for next-generation sequencing reads
- Python 3: Required for HISAT2 indexing and some analysis scripts
- Build tools: For compiling HISAT2 from source

The images are designed to be minimal and focused on a specific version of HISAT2 with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/hisat2:latest
# or
docker pull getwilds/hisat2:2.2.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/hisat2:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/hisat2:latest
# or
apptainer pull docker://getwilds/hisat2:2.2.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/hisat2:latest
```

### Example Commands

```bash
# Building a genome index
docker run --rm -v /path/to/data:/data getwilds/hisat2:latest hisat2-build -p 4 /data/reference.fa /data/reference_index

# Aligning reads to a genome
docker run --rm -v /path/to/data:/data getwilds/hisat2:latest hisat2 -x /data/reference_index -1 /data/reads_1.fq -2 /data/reads_2.fq -S /data/output.sam

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/hisat2:latest hisat2-build -p 4 /data/reference.fa /data/reference_index

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data hisat2_latest.sif hisat2 -x /data/reference_index -1 /data/reads_1.fq -2 /data/reads_2.fq -S /data/output.sam
```

## Security Features

The HISAT2 Docker images include:

- Dynamic versioning for dependencies to ensure the latest security patches
- Pinned versions for reproducibility
- Git-based source code checkout with specific version tagging
- Minimal installation with only required dependencies

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs.txt` file in this directory, which is automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Dynamically determines and pins the latest security-patched versions of dependencies
4. Sets a consistent shell option to fail if any command in a pipe fails
5. Clones the HISAT2 repository from GitHub at a specific version
6. Builds HISAT2 from source
7. Adds HISAT2 to system PATH

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
