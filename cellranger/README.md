# Cell Ranger

This directory contains Docker images for Cell Ranger, 10x Genomics' analysis pipeline for single-cell RNA-seq data.

## Available Versions

- `latest` (currently v10.0.0) ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/cellranger/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/cellranger/CVEs_latest.md) )
- `10.0.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/cellranger/Dockerfile_10.0.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/cellranger/CVEs_10.0.0.md) )
- `6.0.2` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/cellranger/Dockerfile_6.0.2) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/cellranger/CVEs_6.0.2.md) )

## Image Details

These Docker images are built from Ubuntu Noble and include:

- Cell Ranger: A set of analysis pipelines that process Chromium single-cell RNA-seq output to align reads, generate feature-barcode matrices, perform clustering and other secondary analysis

The images are designed to be minimal and focused on Cell Ranger with its dependencies.

## Platform Availability

**AMD64 only**: Cell Ranger only supports x86_64 (AMD64) Linux systems. These images will not run natively on ARM-based systems (e.g., Apple Silicon Macs). Docker Desktop on Apple Silicon can run these images through emulation, though with reduced performance.

## Important Note

**Special Handling Required**: The Cell Ranger download URL contains a signed key that expires. A new download URL should be obtained from 10x Genomics each time the Dockerfiles are updated.

## Usage

### Docker

```bash
docker pull getwilds/cellranger:latest
# or
docker pull getwilds/cellranger:10.0.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/cellranger:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/cellranger:latest
# or
apptainer pull docker://getwilds/cellranger:10.0.0

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
3. Sets shell options for better error handling in pipelines
4. Installs prerequisites with pinned versions
5. Downloads and extracts Cell Ranger pre-built binary using a temporary download link
6. Adds Cell Ranger to the PATH and sets working directory
7. Runs a smoke test to verify the installation

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/cellranger), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
