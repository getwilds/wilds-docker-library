# Samtools

This directory contains Docker images for Samtools, a suite of programs for interacting with high-throughput sequencing data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/samtools/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/samtools/CVEs_latest.md) )
- `1.19` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/samtools/Dockerfile_1.19) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/samtools/CVEs_1.19.md) )
- `1.11` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/samtools/Dockerfile_1.11) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/samtools/CVEs_1.11.md) )
- `1.10` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/samtools/Dockerfile_1.10) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/samtools/CVEs_1.10.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- Samtools: A suite of utilities for manipulating alignments in the SAM/BAM format
- Bedtools: A powerful toolset for genome arithmetic

The images are designed to be minimal and focused on a specific version of Samtools with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/samtools:latest
# or
docker pull getwilds/samtools:1.19
# or
docker pull getwilds/samtools:1.11
# or
docker pull getwilds/samtools:1.10

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/samtools:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/samtools:latest
# or
apptainer pull docker://getwilds/samtools:1.19
# or
apptainer pull docker://getwilds/samtools:1.11
# or
apptainer pull docker://getwilds/samtools:1.10

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/samtools:latest
```

### Example Commands

```bash
# Convert SAM to BAM
docker run --rm -v /path/to/data:/data getwilds/samtools:latest samtools view -bS /data/input.sam > /data/output.bam

# Sort BAM file
docker run --rm -v /path/to/data:/data getwilds/samtools:latest samtools sort /data/input.bam -o /data/sorted.bam

# Index BAM file
docker run --rm -v /path/to/data:/data getwilds/samtools:latest samtools index /data/sorted.bam

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/samtools:latest samtools view -bS /data/input.sam > /data/output.bam

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data samtools_latest.sif samtools sort /data/input.bam -o /data/sorted.bam
```

## Important Note on Temporary Files

For larger file sizes (>30GB), Samtools saves intermediate files to the `/tmp` directory by default. On regulated HPC machinery, that's not always possible due to permissions issues. For these scenarios, we recommend using Samtools v1.19+ and providing a custom temp directory via the `-T` option for a location you are confident you have access to.

Example with custom temp directory:
```bash
# Sort large BAM file with custom temp directory
docker run --rm -v /path/to/data:/data -v /path/to/temp:/temp \
  getwilds/samtools:1.19 samtools sort /data/large_input.bam -o /data/sorted.bam -T /temp/sort_tmp
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Dynamically determines and pins the latest security-patched versions of dependencies
4. Downloads and builds Samtools from source
5. Includes Bedtools for additional functionality
6. Performs cleanup to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/samtools), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
