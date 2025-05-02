# Cell Ranger

This directory contains Docker images for Cell Ranger, 10x Genomics' analysis pipeline for single-cell RNA-seq data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/cellranger/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/cellranger/CVEs_latest.md) )
- `6.0.2` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/cellranger/Dockerfile_6.0.2) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/cellranger/CVEs_6.0.2.md) )

## Image Details

These Docker images are built from Ubuntu Noble and include:

- Cell Ranger v6.0.2: A set of analysis pipelines that process Chromium single-cell RNA-seq output to align reads, generate feature-barcode matrices, perform clustering and other secondary analysis

The images are designed to be minimal and focused on Cell Ranger with its dependencies.

## Important Note

**Special Handling Required**: Due to the download link expiration for Cell Ranger, these containers are excluded from the automated build-and-push GitHub Action. To make changes, provide an updated link and reupload manually.

## Usage

### Docker

```bash
docker pull getwilds/cellranger:latest
# or
docker pull getwilds/cellranger:6.0.2

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/cellranger:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/cellranger:latest
# or
apptainer pull docker://getwilds/cellranger:6.0.2

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/cellranger:latest
```

### Example Commands

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/cellranger:latest cellranger count \
  --id=sample_run \
  --fastqs=/data/fastqs \
  --transcriptome=/data/reference \
  --sample=sample1

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/cellranger:latest cellranger count \
  --id=sample_run \
  --fastqs=/data/fastqs \
  --transcriptome=/data/reference \
  --sample=sample1

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data cellranger_latest.sif cellranger count \
  --id=sample_run \
  --fastqs=/data/fastqs \
  --transcriptome=/data/reference \
  --sample=sample1
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu Noble as the base image
2. Adds metadata labels for documentation and attribution
3. Installs prerequisites with pinned versions
4. Downloads and extracts Cell Ranger source code using a temporary download link
5. Adds Cell Ranger to the PATH
6. Performs cleanup to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/cellranger), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
