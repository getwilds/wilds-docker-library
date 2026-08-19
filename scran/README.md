# scran

This directory contains Docker images for scran, a Bioconductor package providing methods for the analysis of single-cell RNA-seq data, including normalization, highly variable gene detection, and clustering support.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/scran/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/scran/CVEs_latest.md) )
- `1.40.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/scran/Dockerfile_1.40.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/scran/CVEs_1.40.0.md) )

## Image Details

These Docker images are built from the Bioconductor base image (RELEASE_3_23) and include:

- scran v1.40.0: Deconvolution-based normalization, highly variable gene (HVG) detection, quick clustering, marker gene identification, and doublet detection for single-cell RNA-seq data

The images are designed to provide a minimal, focused environment for single-cell RNA-seq preprocessing and normalization with scran itself. Note that Bioconductor documents scran as being in a transitional state, with much of its functionality being superseded by the newer `scrapper` package, though scran remains fully installable and functional.

For quality control and visualization of single-cell data (commonly used alongside scran), see the separate [scater image](https://github.com/getwilds/wilds-docker-library/tree/main/scater).

## Platform Availability

**Note:** This image is only built for **linux/amd64** architecture. scran and its C++ dependencies have compilation issues on ARM64 platforms.

## Citation

If you use scran in your research, please cite the original authors:

```
Lun ATL, McCarthy DJ, Marioni JC (2016). A step-by-step workflow for
low-level analysis of single-cell RNA-seq data with Bioconductor.
F1000Research, 5, 2122. https://doi.org/10.12688/f1000research.9501.2
```

**Tool homepage:** https://bioconductor.org/packages/release/bioc/html/scran.html

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/scran:latest

# Or pull a specific version
docker pull getwilds/scran:1.40.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/scran:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/scran:latest

# Or pull a specific version
apptainer pull docker://getwilds/scran:1.40.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/scran:latest
```

### Example Commands

```bash
# Launch an interactive R session with scran loaded
docker run --rm -it -v /path/to/data:/data getwilds/scran:latest R

# Run an R script that performs a scran normalization/HVG workflow
docker run --rm -v /path/to/data:/data getwilds/scran:latest \
  Rscript /data/scran_analysis.R

# Run a quick inline scran workflow on a saved SingleCellExperiment object
docker run --rm -v /path/to/data:/data getwilds/scran:latest R -e "
  library(scran)
  sce <- readRDS('/data/sce.rds')
  clusters <- quickCluster(sce)
  sce <- computeSumFactors(sce, clusters = clusters)
  sce <- logNormCounts(sce)
  dec <- modelGeneVar(sce)
  top_hvgs <- getTopHVGs(dec, n = 2000)
  saveRDS(sce, '/data/sce_normalized.rds')
  writeLines(top_hvgs, '/data/top_hvgs.txt')
"

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/scran:latest \
  Rscript /data/scran_analysis.R

# Or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data scran_latest.sif \
  Rscript /data/scran_analysis.R
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Bioconductor RELEASE_3_23 as the base image
2. Adds metadata labels for documentation and attribution
3. Sets R library paths to prevent host library contamination in Apptainer
4. Installs scran via BiocManager
5. Runs a smoke test to confirm scran loads and reports its version
6. Sets `/data` as the default working directory

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/scran), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
