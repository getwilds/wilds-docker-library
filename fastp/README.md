# fastp

This directory contains Docker images for [fastp](https://github.com/OpenGene/fastp), an ultra-fast all-in-one FASTQ preprocessor for quality control, adapter trimming, filtering, and read correction.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/fastp/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/fastp/CVEs_latest.md) )
- `1.1.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/fastp/Dockerfile_1.1.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/fastp/CVEs_1.1.0.md) )

## Image Details

These Docker images are built from `condaforge/miniforge3:24.7.1-2` and include:

- fastp v1.1.0: Ultra-fast FASTQ quality control, trimming, filtering, and reporting

The images are designed to be minimal and focused on fastp with its essential dependencies.

## Citation

If you use fastp in your research, please cite the original authors:

```
Shifu Chen. fastp 1.0: An ultra-fast all-round tool for FASTQ data quality
control and preprocessing. iMeta 4.5 (2025): e70078.
https://doi.org/10.1002/imt2.70078
```

**Tool homepage:** https://github.com/OpenGene/fastp

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/fastp:latest

# Or pull a specific version
docker pull getwilds/fastp:1.1.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/fastp:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/fastp:latest

# Or pull a specific version
apptainer pull docker://getwilds/fastp:1.1.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/fastp:latest
```

### Example Commands

```bash
# Basic single-end QC with HTML report
docker run --rm -v /path/to/data:/data getwilds/fastp:latest \
  fastp -i /data/reads.fastq.gz -o /data/reads_filtered.fastq.gz \
  -h /data/report.html -j /data/report.json

# Paired-end QC with adapter auto-detection
docker run --rm -v /path/to/data:/data getwilds/fastp:latest \
  fastp -i /data/R1.fastq.gz -I /data/R2.fastq.gz \
  -o /data/R1_filtered.fastq.gz -O /data/R2_filtered.fastq.gz \
  -h /data/report.html -j /data/report.json

# Paired-end QC with quality and length filtering
docker run --rm -v /path/to/data:/data getwilds/fastp:latest \
  fastp -i /data/R1.fastq.gz -I /data/R2.fastq.gz \
  -o /data/R1_filtered.fastq.gz -O /data/R2_filtered.fastq.gz \
  --qualified_quality_phred 20 --length_required 50 \
  -h /data/report.html -j /data/report.json

# Using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/fastp:latest \
  fastp -i /data/R1.fastq.gz -I /data/R2.fastq.gz \
  -o /data/R1_filtered.fastq.gz -O /data/R2_filtered.fastq.gz
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `condaforge/miniforge3:24.7.1-2` as the base image
2. Adds metadata labels for documentation and attribution
3. Installs fastp v1.1.0 via bioconda using mamba
4. Cleans up conda caches to minimize image size
5. Runs a smoke test to verify the installation

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/fastp), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

---
