# sra-tools

This directory contains Docker images for SRA Toolkit, a collection of tools for accessing data in the NCBI Sequence Read Archive (SRA).

## Available Versions

- `latest`: The most up-to-date stable version (currently SRA-tools v3.1.1)
- `3.1.1`: SRA-tools v3.1.1

## Image Details

These Docker images are built from Conda Forge Miniforge base image and include:

- SRA-tools v3.1.1: Tools for accessing data in the NCBI Sequence Read Archive
- parallel-fastq-dump v0.6.7: A wrapper for fastq-dump with multi-threading support

The images are designed to be minimal and focused on a specific version of SRA Toolkit with its dependencies, optimized for efficient downloading and processing of sequencing data.

## Usage

### Docker

```bash
docker pull getwilds/sra-tools:latest
# or
docker pull getwilds/sra-tools:3.1.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/sra-tools:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/sra-tools:latest
# or
apptainer pull docker://getwilds/sra-tools:3.1.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/sra-tools:latest
```

### Example Commands

```bash
# Download a dataset using fasterq-dump
docker run --rm -v /path/to/data:/data getwilds/sra-tools:latest fasterq-dump SRR12345678 -O /data

# Download using parallel-fastq-dump for better performance
docker run --rm -v /path/to/data:/data getwilds/sra-tools:latest parallel-fastq-dump --sra-id SRR12345678 --threads 8 --outdir /data --split-files

# Prefetch SRA data
docker run --rm -v /path/to/data:/data getwilds/sra-tools:latest prefetch SRR12345678 -O /data

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/sra-tools:latest prefetch SRR12345678 -O /data

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data sra-tools_latest.sif parallel-fastq-dump --sra-id SRR12345678 --threads 8 --outdir /data --split-files
```

## Security Features

The SRA-tools Docker images include:

- Installation through Conda to ensure properly built binaries
- Pinned versions for reproducibility
- Conda configuration to prevent hard-linking for better container compatibility

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in this directory, which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Conda Forge Miniforge as the base image
2. Adds metadata labels for documentation and attribution
3. Configures Conda to use copies instead of hard-links (for compatibility with some filesystems)
4. Installs SRA-tools and parallel-fastq-dump with specific versions through Bioconda

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
