# rtorch

This directory contains Docker images for R with PyTorch integration, providing a CUDA-enabled environment for deep learning in R.

## Available Versions

- `latest`: The most up-to-date stable version (currently torch v0.13.0)
- `0.13.0`: R torch v0.13.0

## Image Details

These Docker images are built from NVIDIA's CUDA 11.7.1 with cuDNN 8 base image and include:

- R 4.1.2: Statistical computing environment
- torch v0.13.0: R interface to the PyTorch deep learning library
- CUDA 11.7.1: For GPU acceleration
- cuDNN 8: Deep Neural Network library

The images are designed to provide a comprehensive environment for deep learning in R with GPU acceleration.

## Usage

### Docker

```bash
docker pull getwilds/rtorch:latest
# or
docker pull getwilds/rtorch:0.13.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/rtorch:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/rtorch:latest
# or
apptainer pull docker://getwilds/rtorch:0.13.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/rtorch:latest
```

### Example Command

```bash
# Docker (using a hypothetical script called "train_model.R")
docker run --gpus all --rm -v /path/to/project:/project getwilds/rtorch:latest Rscript /project/train_model.R

# Apptainer
apptainer run --nv --bind /path/to/project:/project docker://getwilds/rtorch:latest Rscript /project/train_model.R

# Apptainer (local SIF file)
apptainer run --nv --bind /path/to/project:/project rtorch_latest.sif Rscript /project/train_model.R
```

## GPU Support

To use GPU acceleration with this image, ensure that:

1. Your host has NVIDIA drivers installed
2. You have [NVIDIA Container Toolkit](https://github.com/NVIDIA/nvidia-docker) installed
3. You use the `--gpus all` flag when running the container

## Security Features

The rtorch Docker images include:

- Pinned versions for all dependencies to ensure reproducibility
- CUDA and cuDNN integration for GPU acceleration
- Minimal installation with only required packages

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of deep learning frameworks and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs.txt` file in this directory, which is automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses NVIDIA CUDA 11.7.1 with cuDNN 8 as the base image
2. Adds metadata labels for documentation and attribution
3. Sets environment variables for non-interactive installation
4. Installs R and build essentials
5. Installs the torch R package with a specific version
6. Installs PyTorch backends through the R interface

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
