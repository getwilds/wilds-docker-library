# ColabFold

This directory contains Docker images for ColabFold, a tool for fast and accessible protein structure prediction using AlphaFold2 and MMseqs2.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/colabfold/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/colabfold/CVEs_latest.md) )
- `1.5.5` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/colabfold/Dockerfile_1.5.5) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/colabfold/CVEs_1.5.5.md) )

## Image Details

These Docker images are built from NVIDIA's CUDA 11.8.0 base image on Ubuntu 22.04 and include:

- ColabFold v1.5.5: Protein structure prediction using AlphaFold2 with MMseqs2 for fast multiple sequence alignments
- JAX with CUDA support: For GPU-accelerated neural network inference
- NumPy (pinned to <2.0): For numerical computing, pinned to avoid incompatibility with JAX/ColabFold
- Miniforge (conda/mamba): For package management via conda-forge and bioconda channels

The images are designed to provide a GPU-ready ColabFold environment suitable for WDL-based protein structure prediction workflows.

## Platform Availability

**Note:** This image is only built for **linux/amd64** architecture due to CUDA and JAX dependencies.

## GPU Support

To use GPU acceleration with this image, ensure that:

1. Your host has NVIDIA drivers installed
2. You have [NVIDIA Container Toolkit](https://github.com/NVIDIA/nvidia-docker) installed
3. You use the `--gpus all` flag when running the container

## Usage

### Docker

```bash
docker pull getwilds/colabfold:latest
# or
docker pull getwilds/colabfold:1.5.5

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/colabfold:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/colabfold:latest
# or
apptainer pull docker://getwilds/colabfold:1.5.5

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/colabfold:latest
```

### Example Commands

```bash
# Predict structure for a single FASTA file
docker run --gpus all --rm -v /path/to/data:/data getwilds/colabfold:latest \
  colabfold_batch /data/input.fasta /data/output

# Predict using a custom MSA (a3m file)
docker run --gpus all --rm -v /path/to/data:/data getwilds/colabfold:latest \
  colabfold_batch /data/input.a3m /data/output

# Predict with specific options (e.g., number of recycles, amber relaxation)
docker run --gpus all --rm -v /path/to/data:/data getwilds/colabfold:latest \
  colabfold_batch --num-recycle 3 --amber /data/input.fasta /data/output

# Alternatively using Apptainer
apptainer run --nv --bind /path/to/data:/data docker://getwilds/colabfold:latest \
  colabfold_batch /data/input.fasta /data/output

# ... or a local SIF file via Apptainer
apptainer run --nv --bind /path/to/data:/data colabfold_latest.sif \
  colabfold_batch /data/input.fasta /data/output
```

## Citation

If you use ColabFold in your research, please cite the original authors:

```
Mirdita, M., Schütze, K., Moriwaki, Y. et al. ColabFold: making protein folding
accessible to all. Nat Methods 19, 679–682 (2022).
https://doi.org/10.1038/s41592-022-01488-1
```

**Tool homepage:** https://github.com/sokrypton/ColabFold

**Publication:** https://doi.org/10.1038/s41592-022-01488-1

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses NVIDIA CUDA 11.8.0 on Ubuntu 22.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system dependencies (wget, cuda-nvcc) with pinned versions
4. Downloads and installs Miniforge for conda/mamba package management
5. Creates a dedicated conda environment with ColabFold, CUDA-enabled JAX, and NumPy <2
6. Configures environment variables for conda paths and matplotlib backend
7. Creates a writable cache directory for WDL task compatibility
8. Runs a smoke test to verify ColabFold installation

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/colabfold), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
