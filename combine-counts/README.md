# combine-counts

This directory contains Docker images for combine-counts, a Python-based toolkit for combining STAR RNA-seq count matrices for downstream analysis in DESeq2.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/combine-counts/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/combine-counts/CVEs_latest.md) )
- `0.1.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/combine-counts/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/combine-counts/CVEs_0.1.0.md) )

## Image Details

These Docker images are built from the Python 3.12-slim base image and include:

- combine_star_counts.py: A Python script for combining individual STAR count matrices into a single matrix
- pandas: Python data manipulation library for efficient data processing
- Template generation for DESeq2 sample metadata

The images are designed to provide a streamlined environment for preparing RNA-seq count data for differential expression analysis.

## Usage

### Docker

```bash
docker pull getwilds/combine-counts:latest

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/combine-counts:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/combine-counts:latest

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/combine-counts:latest
```

### Example Commands

```bash
# Docker - Process multiple count files
docker run --rm -v /path/to/data:/data getwilds/combine-counts:latest python /usr/combine-counts/combine_star_counts.py \
  --input /data/sample1.ReadsPerGene.out.tab /data/sample2.ReadsPerGene.out.tab /data/sample3.ReadsPerGene.out.tab \
  --output /data/combined_counts.txt \
  --metadata /data/sample_metadata.txt

# With stranded RNA-seq data (column 3 = forward strand, column 4 = reverse strand)
docker run --rm -v /path/to/data:/data getwilds/combine-counts:latest python /usr/combine-counts/combine_star_counts.py \
  --input /data/sample1.ReadsPerGene.out.tab /data/sample2.ReadsPerGene.out.tab \
  --output /data/combined_counts.txt \
  --count_column 3

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/combine-counts:latest python /usr/combine-counts/combine_star_counts.py \
  --input /data/sample1.ReadsPerGene.out.tab /data/sample2.ReadsPerGene.out.tab \
  --output /data/combined_counts.txt

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data combine-counts_latest.sif python /usr/combine-counts/combine_star_counts.py \
  --input /data/sample1.ReadsPerGene.out.tab /data/sample2.ReadsPerGene.out.tab \
  --output /data/combined_counts.txt
```

## Security Features

The combine-counts Docker images include:

- Python 3.12 slim base for minimal attack surface
- Pinned versions for all dependencies to ensure reproducibility
- Minimal installation with only required dependencies
- Permission settings to ensure script execution

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/combine-counts), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Python 3.12-slim as the base image
2. Adds metadata labels for documentation and attribution
3. Installs pandas with a pinned version
4. Copies the combine_star_counts.py script to the container
5. Makes the script executable and adds it to PATH
6. Sets up appropriate working directories

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
