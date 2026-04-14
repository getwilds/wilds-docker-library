# PopV

This directory contains Docker images for PopV (Popular Vote), a tool for automated consensus cell-type annotation of single-cell RNA-seq data. PopV runs multiple cell-type classification algorithms and computes agreement between them to predict cell types in a query dataset based on a reference dataset.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/popv/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/popv/CVEs_latest.md) )
- `0.6.1` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/popv/Dockerfile_0.6.1) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/popv/CVEs_0.6.1.md) )

## Image Details

These Docker images are built from `nvidia/cuda:12.6.3-runtime-ubuntu24.04` (for GPU support via PyTorch/scvi-tools) and include:

- PopV v0.6.1: Consensus cell-type annotation using multiple classification algorithms and bundled models
- PyTorch v2.6.0 with CUDA 12.6 wheels
- JupyterLab v4.5.6: Interactive notebook environment for running PopV analyses

The images are designed to be minimal and focused on PopV with its essential dependencies. GPU acceleration requires an NVIDIA GPU on the host and the NVIDIA Container Toolkit; pass `--gpus all` to `docker run` (or `--nv` to `apptainer run`) to expose the GPU inside the container. The images still run on CPU-only hosts if no GPU is available.

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
# Run a Python script that uses PopV for cell-type annotation (GPU-enabled)
docker run --rm --gpus all -v /path/to/data:/data getwilds/popv:latest \
  python3 /data/annotate_cells.py

# Start an interactive Python session with PopV available
docker run --rm -it --gpus all -v /path/to/data:/data getwilds/popv:latest python3

# Launch a JupyterLab notebook server
docker run --rm -it --gpus all -p 8888:8888 -v /path/to/data:/data getwilds/popv:latest \
  jupyter lab --ip=0.0.0.0 --allow-root --no-browser --notebook-dir=/data

# Run a one-liner to verify the installation
docker run --rm getwilds/popv:latest \
  python3 -c "import popv; print(popv.__version__)"

# Using Apptainer (use --nv to expose the host GPU)
apptainer run --nv --bind /path/to/data:/data docker://getwilds/popv:latest \
  python3 /data/annotate_cells.py

# Launch JupyterLab via Apptainer, then open the URL printed in the terminal
apptainer run --nv --bind /path/to/data:/data docker://getwilds/popv:latest \
  jupyter lab --ip=0.0.0.0 --allow-root --no-browser --notebook-dir=/data

# Launch JupyterLab on an HPC cluster (e.g., Fred Hutch)
# First, grab a GPU compute node rather than running on the head/login node:
#   grabnode  (see https://sciwiki.fredhutch.org/compdemos/grabnode/)
# Then, from the compute node:
export PORT=$(fhfreeport)
apptainer run --nv --bind /path/to/data:/data docker://getwilds/popv:latest \
  jupyter lab --ip=$(hostname) --port=$PORT --no-browser --notebook-dir=/data
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `nvidia/cuda:12.6.3-runtime-ubuntu24.04` as the base image for GPU support
2. Adds metadata labels for documentation and attribution
3. Installs Python 3 and system build dependencies (gcc, g++) with pinned versions
4. Installs PyTorch (CUDA 12.6 wheels), PopV, JupyterLab, and all Python dependencies via pip
5. Purges build toolchain and cleans up apt lists to minimize image size
6. Runs a smoke test to verify the installation

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/popv), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

---
