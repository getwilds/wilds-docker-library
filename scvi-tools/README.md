# scvi-tools

This directory contains Docker images for scvi-tools, a package for probabilistic modeling of single-cell omics data, focused on deep generative models.

## Available Versions

- `latest`: The most up-to-date stable version (currently scvi-tools v1.1.6)
- `1.1.6`: scvi-tools v1.1.6

## Image Details

These Docker images are built from Python 3.12-slim and include:

- scvi-tools v1.1.6: Deep probabilistic analysis of single-cell omics data
- scanpy v1.10.2: Single-Cell Analysis in Python
- PyTorch v2.4.0: Deep learning framework
- leiden-clustering v0.1.0: Community detection for single-cell data
- scikit-misc v0.5.1: Miscellaneous scikit additions

The images are designed to provide a comprehensive environment for single-cell analysis with deep learning capabilities and CUDA support.

## Usage

### Docker

```bash
docker pull getwilds/scvi-tools:latest
# or
docker pull getwilds/scvi-tools:1.1.6

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/scvi-tools:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/scvi-tools:latest
# or
apptainer pull docker://getwilds/scvi-tools:1.1.6

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/scvi-tools:latest
```

### Example Command

```bash
# Run a Python script with GPU support
docker run --gpus all --rm -v /path/to/project:/project getwilds/scvi-tools:latest python /project/analyze_scRNA.py
```

## GPU Support

This image includes CUDA-enabled PyTorch (cu118). To use GPU acceleration:

1. Your host needs NVIDIA drivers installed
2. You need the [NVIDIA Container Toolkit](https://github.com/NVIDIA/nvidia-docker) installed
3. Use the `--gpus all` flag when running the container

## Security Features

The scvi-tools Docker images include:

- Python 3.12-slim base for minimal attack surface
- Pinned versions for all dependencies to ensure reproducibility
- Installation via pip with no-cache-dir to keep image size minimal

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of deep learning frameworks and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs.txt` file in this directory, which is automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Python 3.12-slim as the base image
2. Adds metadata labels for documentation and attribution
3. Installs scvi-tools, scanpy, and leiden-clustering with pinned versions
4. Installs PyTorch with CUDA support from the PyTorch index

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
