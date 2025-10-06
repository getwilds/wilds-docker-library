# rnaseqc

This directory contains Docker images for RNA-SeQC, a tool for quality control metrics on RNA-sequencing data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/rnaseqc/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/rnaseqc/CVEs_latest.md) )
- `2.4.2` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/rnaseqc/Dockerfile_2.4.2) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/rnaseqc/CVEs_2.4.2.md) )

## Image Details

These Docker images are built from Ubuntu (24.04) and include:

- RNA-SeQC v2.4.2: A robust quality control tool for RNA sequencing data
- OpenJDK 17: Required Java runtime for RNA-SeQC
- R-base: For generating plots and reports

The images are designed to be minimal and focused on a specific version of RNA-SeQC with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/rnaseqc:latest
# or
docker pull getwilds/rnaseqc:2.4.2

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/rnaseqc:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/rnaseqc:latest
# or
apptainer pull docker://getwilds/rnaseqc:2.4.2

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/rnaseqc:latest
```

### Example Command

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/rnaseqc:latest rnaseqc \
  /data/genes.gtf \
  /data/aligned.bam \
  /data/output_directory \
  --sample=sample_name

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/rnaseqc:latest rnaseqc \
  /data/genes.gtf \
  /data/aligned.bam \
  /data/output_directory \
  --sample=sample_name

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data rnaseqc_latest.sif rnaseqc \
  /data/genes.gtf \
  /data/aligned.bam \
  /data/output_directory \
  --sample=sample_name
```

## Security Features

The RNA-SeQC Docker images include:

- OpenJDK 17 with the latest security patches
- Pinned versions for all dependencies to ensure reproducibility
- CA certificates update for secure connections
- Minimal installation with only required dependencies

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/rnaseqc), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu (24.04) as the base image
2. Adds metadata labels for documentation and attribution
3. Sets environment variables for non-interactive installation
4. Installs OpenJDK 17 with pinned version
5. Installs supporting packages (wget, ant, r-base)
6. Downloads RNA-SeQC executable from GitHub releases
7. Configures the Java environment
8. Makes RNA-SeQC executable and adds it to PATH

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
