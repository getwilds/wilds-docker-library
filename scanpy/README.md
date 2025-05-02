# Scanpy

This directory contains Docker images for Scanpy, a Python-based toolkit for analyzing single-cell gene expression data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/scanpy/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/scanpy/CVEs_latest.md) )
- `1.10.2` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/scanpy/Dockerfile_1.10.2) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/scanpy/CVEs_1.10.2.md) )

## Image Details

These Docker images are built from the Python 3.12 slim image and include:

- Scanpy v1.10.2: A scalable toolkit for analyzing single-cell gene expression data
- leiden-clustering v0.1.0: For community detection in networks, required for Scanpy's clustering functionality

The images are designed to be minimal and focused on Scanpy with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/scanpy:latest
# or
docker pull getwilds/scanpy:1.10.2

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/scanpy:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/scanpy:latest
# or
apptainer pull docker://getwilds/scanpy:1.10.2

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/scanpy:latest
```

### Example Python Script

```python
# example.py
import scanpy as sc
import matplotlib.pyplot as plt

# Load data
adata = sc.read_10x_mtx('/data/filtered_feature_bc_matrix/')

# Preprocess
sc.pp.filter_cells(adata, min_genes=200)
sc.pp.filter_genes(adata, min_cells=3)
sc.pp.normalize_per_cell(adata)
sc.pp.log1p(adata)
sc.pp.highly_variable_genes(adata, n_top_genes=2000)

# PCA and UMAP
sc.tl.pca(adata)
sc.pp.neighbors(adata)
sc.tl.umap(adata)

# Clustering
sc.tl.leiden(adata)

# Save results
adata.write('/data/results.h5ad')

# Plot
sc.pl.umap(adata, color='leiden', save='/data/umap.pdf')
```

Run the script with:

```bash
# Docker
docker run --rm -v /path/to/data:/data -v /path/to/script:/script getwilds/scanpy:latest python /script/example.py

# Apptainer
apptainer run --bind /path/to/data:/data,/path/to/script:/script docker://getwilds/scanpy:latest python /script/example.py

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data,/path/to/script:/script scanpy_latest.sif python /script/example.py
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Python 3.12 slim as the base image
2. Adds metadata labels for documentation and attribution
3. Installs Scanpy and leiden-clustering via pip with pinned versions
4. Uses `--no-cache-dir` to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/scanpy), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
