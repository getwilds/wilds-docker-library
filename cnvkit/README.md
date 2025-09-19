# cnvkit

This directory contains Docker images for CNVkit, a Python toolkit for detecting copy number variants from high-throughput sequencing data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/cnvkit/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/cnvkit/CVEs_latest.md) )
- `0.9.10` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/cnvkit/Dockerfile_0.9.10) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/cnvkit/CVEs_0.9.10.md) )

## Image Details

These Docker images are built from Python slim base image and include:

- Python 3.10: The core programming language (optimized for CNVkit compatibility)
- CNVkit 0.9.10: A Python library and command-line software toolkit for detecting copy number variants and alterations from high-throughput sequencing
- R base: Required for certain CNVkit statistical functions
- R packages: Essential Bioconductor and CRAN packages (DNAcopy, PSCBS, GenomicRanges, IRanges, ggplot2, gridExtra, RColorBrewer, BiocManager)
- Build tools: Essential compilation tools for native dependencies

The images are designed to be secure and reliable while including all necessary components for CNVkit analysis of genomic data.

## Usage

### Docker

```bash
docker pull getwilds/cnvkit:latest
# or
docker pull getwilds/cnvkit:0.9.10

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/cnvkit:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/cnvkit:latest
# or
apptainer pull docker://getwilds/cnvkit:0.9.10

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/cnvkit:latest
```

### Example Commands

```bash
# Run CNVkit batch analysis with Docker
docker run --rm -v /path/to/data:/data getwilds/cnvkit:latest cnvkit.py batch \
  /data/tumor.bam \
  --normal /data/normal.bam \
  --targets /data/targets.bed \
  --fasta /data/reference.fa \
  --output-dir /data/results \
  --processes 4

# Generate a copy number scatter plot
docker run --rm -v /path/to/data:/data getwilds/cnvkit:latest cnvkit.py scatter \
  /data/results/tumor.cnr \
  -s /data/results/tumor.cns \
  -o /data/results/tumor_scatter.pdf

# With Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/cnvkit:latest cnvkit.py batch \
  /data/tumor.bam \
  --normal /data/normal.bam \
  --targets /data/targets.bed \
  --fasta /data/reference.fa \
  --output-dir /data/results \
  --processes 4
```

## Security Features

The CNVkit Docker images include:

- Installation through pip to ensure properly built packages
- Pinned versions for reproducibility (including Cython and NumPy compatibility versions)
- Minimal dependencies to reduce attack surface
- Health checks for container monitoring
- Proper working directory setup

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/cnvkit), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Python 3.10-slim as the base image for optimal compatibility
2. Adds metadata labels for documentation and attribution
3. Sets environment variables for Python optimization
4. Installs system dependencies (R, build tools, BLAS/LAPACK libraries) with pinned versions
5. Sets working directory
6. Installs CNVkit 0.9.10 with compatible dependency versions (Cython <3.0, NumPy <1.25)
7. Installs essential R packages for CNVkit functionality
8. Configures health checks and default command

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
