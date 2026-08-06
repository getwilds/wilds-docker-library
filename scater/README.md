# scater

This directory contains Docker images for scater, a Bioconductor package for quality control, normalization, and visualization of single-cell RNA-seq gene expression data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/scater/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/scater/CVEs_latest.md) )
- `1.40.2` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/scater/Dockerfile_1.40.2) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/scater/CVEs_1.40.2.md) )

## Image Details

These Docker images are built from the Bioconductor base image (RELEASE_3_23) and include:

- scater v1.40.2: Quality control metrics, dimensionality reduction (PCA, t-SNE, UMAP), and a wide range of diagnostic plots for single-cell RNA-seq data

The images are designed to provide a minimal, focused environment for single-cell RNA-seq quality control and visualization with scater itself.

## Platform Availability

**Note:** This image is only built for **linux/amd64** architecture. scater and its C++ dependencies have compilation issues on ARM64 platforms.

## Citation

If you use scater in your research, please cite the original authors:

```
McCarthy DJ, Campbell KR, Lun ATL, Wills QF (2017). Scater: pre-processing,
quality control, normalization and visualization of single-cell RNA-seq data
in R. Bioinformatics, 33(8), 1179-1186.
https://doi.org/10.1093/bioinformatics/btw777
```

**Tool homepage:** https://bioconductor.org/packages/release/bioc/html/scater.html

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/scater:latest

# Or pull a specific version
docker pull getwilds/scater:1.40.2

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/scater:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/scater:latest

# Or pull a specific version
apptainer pull docker://getwilds/scater:1.40.2

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/scater:latest
```

### Example Commands

```bash
# Launch an interactive R session with scater loaded
docker run --rm -it -v /path/to/data:/data getwilds/scater:latest R

# Run an R script that performs a scater QC/visualization workflow
docker run --rm -v /path/to/data:/data getwilds/scater:latest \
  Rscript /data/scater_analysis.R

# Run a quick inline scater QC workflow on a saved SingleCellExperiment object
docker run --rm -v /path/to/data:/data getwilds/scater:latest R -e "
  library(scater)
  sce <- readRDS('/data/sce.rds')
  sce <- addPerCellQC(sce)
  sce <- runPCA(sce)
  png('/data/qc_pca.png')
  print(plotPCA(sce, colour_by = 'sum'))
  dev.off()
  saveRDS(sce, '/data/sce_qc.rds')
"

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/scater:latest \
  Rscript /data/scater_analysis.R

# Or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data scater_latest.sif \
  Rscript /data/scater_analysis.R
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Bioconductor RELEASE_3_23 as the base image
2. Adds metadata labels for documentation and attribution
3. Sets R library paths to prevent host library contamination in Apptainer
4. Installs scater via BiocManager
5. Runs a smoke test to confirm scater loads and reports its version
6. Sets `/data` as the default working directory

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/scater), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
