# STARLING

This directory contains Docker images for [STARLING](https://github.com/idptools/starling), a latent-space probabilistic denoising diffusion model for predicting coarse-grained ensembles of intrinsically disordered protein regions from amino acid sequences.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/starling/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/starling/CVEs_latest.md) )
- `2.0.0a3` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/starling/Dockerfile_2.0.0a3) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/starling/CVEs_2.0.0a3.md) )

## Image Details

These Docker images are built from `python:3.11-slim` and include:

- STARLING v2.0.0a3: Coarse-grained ensemble prediction for intrinsically disordered proteins
- PyTorch: Deep learning framework used by STARLING's diffusion model
- MDTraj: Molecular dynamics trajectory analysis
- metapredict: Disorder prediction used internally by STARLING

The images are designed to be minimal and focused on STARLING with its essential dependencies.

## Citation

If you use STARLING in your research, please cite the original authors:

```
Novak B, Lotthammer JM, Emenecker RJ, Holehouse AS.
Accurate predictions of conformational ensembles of disordered proteins with STARLING.
bioRxiv 2025.02.14.638373 (2025).
DOI: 10.1101/2025.02.14.638373
```

**Tool homepage:** https://github.com/idptools/starling

**Publication:** https://doi.org/10.1101/2025.02.14.638373

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/starling:latest

# Or pull a specific version
docker pull getwilds/starling:2.0.0a3

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/starling:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/starling:latest

# Or pull a specific version
apptainer pull docker://getwilds/starling:2.0.0a3

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/starling:latest
```

### Example Commands

```bash
# Generate an ensemble for a disordered protein sequence
docker run --rm -v /path/to/data:/data getwilds/starling:latest \
  starling --sequence MKVIFLAVLGLGIVVTTVLY --output /data/ensemble.starling

# Generate an ensemble from a FASTA file
docker run --rm -v /path/to/data:/data getwilds/starling:latest \
  starling --fasta /data/sequences.fasta --output /data/ensemble.starling

# Convert a STARLING output file to PDB + XTC trajectory
docker run --rm -v /path/to/data:/data getwilds/starling:latest \
  starling2xtc --input /data/ensemble.starling --output /data/ensemble

# Query information about a .starling file
docker run --rm -v /path/to/data:/data getwilds/starling:latest \
  starling2info --input /data/ensemble.starling

# Using Apptainer to generate an ensemble
apptainer run --bind /path/to/data:/data docker://getwilds/starling:latest \
  starling --sequence MKVIFLAVLGLGIVVTTVLY --output /data/ensemble.starling
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `python:3.11-slim` as the base image
2. Adds metadata labels for documentation and attribution
3. Installs build dependencies (gcc, g++, make) needed for Cython compilation
4. Installs STARLING v2.0.0a3 and all Python dependencies via pip
5. Removes build dependencies to minimize image size
6. Performs a smoke test to verify the installation
7. Cleans up apt caches to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/starling), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

---
