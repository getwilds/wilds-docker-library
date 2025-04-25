# sourmash

This directory contains Docker images for sourmash, a tool for computing and comparing MinHash signatures for DNA sequences.

## Available Versions

- `latest`: The most up-to-date stable version (currently sourmash v4.8.2)
- `4.8.2`: sourmash v4.8.2

## Image Details

These Docker images are built from Conda Forge Miniforge base image and include:

- Python 3.10: Core programming language
- sourmash-minimal v4.8.2: A tool for rapid genome and metagenome comparison using MinHash sketches

The images are designed to be minimal and focused on a specific version of sourmash with its dependencies, optimized for metagenomics and genomic comparison tasks.

## Usage

### Docker

```bash
docker pull getwilds/sourmash:latest
# or
docker pull getwilds/sourmash:4.8.2

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/sourmash:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/sourmash:latest
# or
apptainer pull docker://getwilds/sourmash:4.8.2

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/sourmash:latest
```

### Example Commands

```bash
# Compute a signature for a genome
docker run --rm -v /path/to/data:/data getwilds/sourmash:latest sourmash compute /data/genome.fa -o /data/genome.sig

# Compare signatures
docker run --rm -v /path/to/data:/data getwilds/sourmash:latest sourmash compare /data/*.sig -o /data/comparison.matrix

# Generate a plot from comparison
docker run --rm -v /path/to/data:/data getwilds/sourmash:latest sourmash plot /data/comparison.matrix -o /data/comparison.plot

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/sourmash:latest sourmash compute /data/genome.fa -o /data/genome.sig

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data sourmash_latest.sif sourmash compare /data/*.sig -o /data/comparison.matrix
```

## Security Features

The sourmash Docker images include:

- Installation through Conda to ensure properly built binaries
- Pinned versions for reproducibility
- Conda environment cleanup to minimize image size
- Non-interactive Conda configuration

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs.txt` file in this directory, which is automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Conda Forge Miniforge as the base image
2. Adds metadata labels for documentation and attribution
3. Configures Conda to run in non-interactive mode
4. Sets up the shell for proper conda environment activation
5. Installs Python 3.10 and sourmash-minimal with specific versions
6. Cleans Conda caches to minimize image size
7. Verifies installation with version check
8. Sets the default entrypoint to bash

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
