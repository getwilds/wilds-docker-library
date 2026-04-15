# Trim Galore

This directory contains Docker images for [Trim Galore](https://github.com/FelixKrueger/TrimGalore), a wrapper around Cutadapt and FastQC that consistently applies adapter and quality trimming to FASTQ files, with additional functionality for RRBS (Reduced Representation Bisulfite Sequencing) data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/trim-galore/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/trim-galore/CVEs_latest.md) )
- `0.6.11` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/trim-galore/Dockerfile_0.6.11) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/trim-galore/CVEs_0.6.11.md) )

## Image Details

These Docker images are built from `condaforge/miniforge3:24.7.1-2` and include:

- Trim Galore v0.6.11: Adapter and quality trimming wrapper for FASTQ files
- Cutadapt: The underlying adapter trimming engine
- FastQC: Quality control reporting for sequencing data
- pigz: Parallel gzip compression for faster I/O

The images are designed to be minimal and focused on Trim Galore with its essential dependencies.

## Citation

If you use Trim Galore in your research, please cite the original author:

```
Felix Krueger. Trim Galore.
https://github.com/FelixKrueger/TrimGalore
DOI: 10.5281/zenodo.5127899
```

**Tool homepage:** https://github.com/FelixKrueger/TrimGalore

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/trim-galore:latest

# Or pull a specific version
docker pull getwilds/trim-galore:0.6.11

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/trim-galore:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/trim-galore:latest

# Or pull a specific version
apptainer pull docker://getwilds/trim-galore:0.6.11

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/trim-galore:latest
```

### Example Commands

```bash
# Trim a single-end FASTQ file with default settings
docker run --rm -v /path/to/data:/data getwilds/trim-galore:latest \
  trim_galore /data/sample.fastq.gz -o /data/trimmed

# Trim paired-end FASTQ files
docker run --rm -v /path/to/data:/data getwilds/trim-galore:latest \
  trim_galore --paired /data/sample_R1.fastq.gz /data/sample_R2.fastq.gz -o /data/trimmed

# Trim with FastQC reports generated automatically
docker run --rm -v /path/to/data:/data getwilds/trim-galore:latest \
  trim_galore --fastqc --paired /data/sample_R1.fastq.gz /data/sample_R2.fastq.gz -o /data/trimmed

# Trim RRBS data (bisulfite sequencing)
docker run --rm -v /path/to/data:/data getwilds/trim-galore:latest \
  trim_galore --rrbs --paired /data/rrbs_R1.fastq.gz /data/rrbs_R2.fastq.gz -o /data/trimmed

# Using Apptainer to trim paired-end reads with quality threshold
apptainer run --bind /path/to/data:/data docker://getwilds/trim-galore:latest \
  trim_galore --quality 30 --paired /data/sample_R1.fastq.gz /data/sample_R2.fastq.gz -o /data/trimmed
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `condaforge/miniforge3:24.7.1-2` as the base image
2. Adds metadata labels for documentation and attribution
3. Installs Trim Galore v0.6.11 via mamba from the bioconda channel (includes Cutadapt, FastQC, and pigz)
4. Performs a smoke test to verify the installation of Trim Galore, Cutadapt, and FastQC
5. Cleans up conda caches to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/trim-galore), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

---
