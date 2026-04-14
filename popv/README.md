# PopV

This directory contains Docker images for PopV (Popular Vote), a tool for automated consensus cell-type annotation of single-cell RNA-seq data. PopV runs multiple cell-type classification algorithms and computes agreement between them to predict cell types in a query dataset based on a reference dataset.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/popv/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/popv/CVEs_latest.md) )
- `0.6.1` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/popv/Dockerfile_0.6.1) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/popv/CVEs_0.6.1.md) )

## Image Details

These Docker images are built from `python:3.11-slim` and include:

- PopV v0.6.1: Consensus cell-type annotation using multiple classification algorithms and bundled models
- JupyterLab v4.5.6: Interactive notebook environment for running PopV analyses

The images are designed to be minimal and focused on PopV with its essential dependencies.

## Citation

If you use PopV in your research, please cite the original authors:

```
Ergen, C. et al. (2023). PopV: Reproducible and automated cell type annotation
using consensus of classification algorithms. bioRxiv.
https://doi.org/10.1101/2023.08.18.553912
```

**Tool homepage:** https://github.com/YosefLab/popV

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/popv:latest

# Or pull a specific version
docker pull getwilds/popv:0.6.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/popv:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/popv:latest

# Or pull a specific version
apptainer pull docker://getwilds/popv:0.6.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/popv:latest
```

### Example Commands

```bash
# Run a Python script that uses PopV for cell-type annotation
docker run --rm -v /path/to/data:/data getwilds/popv:latest \
  python /data/annotate_cells.py

# Start an interactive Python session with PopV available
docker run --rm -it -v /path/to/data:/data getwilds/popv:latest python

# Launch a JupyterLab notebook server
docker run --rm -it -p 8888:8888 -v /path/to/data:/data getwilds/popv:latest \
  jupyter lab --ip=0.0.0.0 --allow-root --no-browser --notebook-dir=/data

# Run a one-liner to verify the installation
docker run --rm getwilds/popv:latest \
  python -c "import popv; print(popv.__version__)"

# Using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/popv:latest \
  python /data/annotate_cells.py

# Launch JupyterLab via Apptainer, then open the URL printed in the terminal
apptainer run --bind /path/to/data:/data docker://getwilds/popv:latest \
  jupyter lab --ip=0.0.0.0 --allow-root --no-browser --notebook-dir=/data

# Launch JupyterLab on an HPC cluster (e.g., Fred Hutch)
# First, grab a compute node rather than running on the head/login node:
#   grabnode  (see https://sciwiki.fredhutch.org/compdemos/grabnode/)
# Then, from the compute node:
export PORT=$(fhfreeport)
apptainer run --bind /path/to/data:/data docker://getwilds/popv:latest \
  jupyter lab --ip=$(hostname) --port=$PORT --no-browser --notebook-dir=/data
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `python:3.11-slim` as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system build dependencies (gcc, g++) with pinned versions
4. Installs PopV, JupyterLab, and all Python dependencies via pip
5. Runs a smoke test to verify the installation
6. Cleans up apt lists to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/popv), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

---
