# BCFtools

This directory contains Docker images for BCFtools, a set of utilities for variant calling and manipulating VCF/BCF files.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bcftools/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/bcftools/CVEs_latest.md) )
- `1.19` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bcftools/Dockerfile_1.19) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/bcftools/CVEs_1.19.md) )
- `1.11` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bcftools/Dockerfile_1.11) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/bcftools/CVEs_1.11.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- BCFtools: A set of utilities for variant calling and manipulating files in the Variant Call Format (VCF) and its binary counterpart BCF

The images are designed to be minimal and focused on a specific version of BCFtools with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/bcftools:latest
# or
docker pull getwilds/bcftools:1.19
# or
docker pull getwilds/bcftools:1.11

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/bcftools:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/bcftools:latest
# or
apptainer pull docker://getwilds/bcftools:1.19
# or
apptainer pull docker://getwilds/bcftools:1.11

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/bcftools:latest
```

### Example Commands

```bash
# Call variants
docker run --rm -v /path/to/data:/data getwilds/bcftools:latest bcftools mpileup -f /data/reference.fa /data/aligned.bam | bcftools call -mv -Ob -o /data/calls.bcf

# Convert BCF to VCF
docker run --rm -v /path/to/data:/data getwilds/bcftools:latest bcftools view /data/calls.bcf > /data/calls.vcf

# Filter variants
docker run --rm -v /path/to/data:/data getwilds/bcftools:latest bcftools filter -i 'QUAL>20' /data/calls.vcf > /data/filtered.vcf

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bcftools:latest bcftools mpileup -f /data/reference.fa /data/aligned.bam | bcftools call -mv -Ob -o /data/calls.bcf

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data bcftools_latest.sif bcftools mpileup -f /data/reference.fa /data/aligned.bam | bcftools call -mv -Ob -o /data/calls.bcf
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Dynamically determines and pins the latest security-patched versions of dependencies
4. Downloads and builds BCFtools from source
5. Performs cleanup to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/bcftools), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
