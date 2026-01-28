# JCAST

This directory contains Docker images for JCAST, a Python tool for generating alternative splicing-derived protein sequences from RNA-seq data for proteomics analysis.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/jcast/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/jcast/CVEs_latest.md) )
- `0.3.5` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/jcast/Dockerfile_0.3.5) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/jcast/CVEs_0.3.5.md) )

## Image Details

These Docker images are built from the Python 3.11 slim image and include:

- JCAST v0.3.5: A tool for translating alternative splicing events (e.g., from rMATS output) into protein sequences for mass spectrometry-based proteomics

The images are designed to be minimal and focused on JCAST with its dependencies.

## Citation

If you use JCAST in your research, please cite the original authors:

```
Ludwig, R.W. and Lau, E. (2021). JCAST: Sample-Specific Protein Isoform Databases
for Mass Spectrometry-based Proteomics Experiments. Software Impacts, 10, 100163.
```

**Tool homepage:** https://github.com/ed-lau/jcast

## Usage

### Docker

```bash
docker pull getwilds/jcast:latest
# or
docker pull getwilds/jcast:0.3.5

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/jcast:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/jcast:latest
# or
apptainer pull docker://getwilds/jcast:0.3.5

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/jcast:latest
```

### Example Usage

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/jcast:latest jcast -r /data/rmats_output -g /data/genome.fa -o /data/jcast_output

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/jcast:latest jcast -r /data/rmats_output -g /data/genome.fa -o /data/jcast_output

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data jcast_latest.sif jcast -r /data/rmats_output -g /data/genome.fa -o /data/jcast_output
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Python 3.11 slim as the base image
2. Adds metadata labels for documentation and attribution
3. Installs build dependencies (`gcc`, `g++`) needed to compile JCAST's `pomegranate` dependency
4. Installs JCAST via pip with a pinned version and `--no-cache-dir`
5. Removes build dependencies and cleans up apt lists to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/jcast), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
