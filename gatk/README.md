# GATK

This directory contains Docker images for the Genome Analysis Toolkit (GATK), a software package developed by the Broad Institute for analyzing high-throughput sequencing data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/gatk/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/gatk/CVEs_latest.md) )
- `4.3.0.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/gatk/Dockerfile_4.3.0.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/gatk/CVEs_4.3.0.0.md) )

## Image Details

These Docker images are built from Conda Forge Miniforge base image and include:

- GATK4 v4.3.0.0: A toolkit for variant discovery in high-throughput sequencing data
- Samtools v1.11: A suite of programs for interacting with high-throughput sequencing data

The images are designed to be minimal and focused on a specific version of GATK with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/gatk:latest
# or
docker pull getwilds/gatk:4.3.0.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/gatk:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/gatk:latest
# or
apptainer pull docker://getwilds/gatk:4.3.0.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/gatk:latest
```

### Example Command

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/gatk:latest gatk HaplotypeCaller -R reference.fa -I input.bam -O output.vcf

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/gatk:latest gatk HaplotypeCaller -R reference.fa -I input.bam -O output.vcf

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data gatk_latest.sif gatk HaplotypeCaller -R reference.fa -I input.bam -O output.vcf
```

## Security Features

The GATK Docker images include:

- Installation through Conda to ensure properly built binaries
- Pinned versions for reproducibility
- Minimal installation with only required dependencies
- Samtools built from source with appropriate security considerations

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/gatk), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Conda Forge Miniforge as the base image
2. Adds metadata labels for documentation and attribution
3. Installs GATK4 via Conda
4. Installs dependencies for building Samtools
5. Downloads and builds Samtools v1.11 from source
6. Cleans up build artifacts to minimize image size

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
