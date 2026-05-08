# DESeq2

This directory contains Docker images for DESeq2, a Bioconductor package for differential expression analysis of RNA-seq count data.

## Available Versions

- `latest`: The most up-to-date stable version (currently DESeq2 v1.40.2 from Bioconductor 3.17)
- `1.40.2`: DESeq2 v1.40.2 from Bioconductor 3.17

## Image Details

These Docker images are built from the Bioconductor base image and include:

- DESeq2 v1.40.2: A package for differential expression analysis of RNA-seq count data
- pasilla: Example RNA-seq dataset from Drosophila for testing and tutorials
- apeglm: For LFC shrinkage estimation
- pheatmap & RColorBrewer: For visualization of differential expression results
- optparse, ggplot2, dplyr: For command-line interface and data processing

The images are designed to provide a comprehensive environment for RNA-seq differential expression analysis with DESeq2 methodology, including example data for testing and learning purposes.

## Platform Availability

**Note:** This image is only built for **linux/amd64** architecture. DESeq2 and its dependencies have compilation issues on ARM64 platforms.

## Usage

### Docker

```bash
docker pull getwilds/deseq2:latest
# or
docker pull getwilds/deseq2:1.40.2

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/deseq2:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/deseq2:latest
# or
apptainer pull docker://getwilds/deseq2:1.40.2

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/deseq2:latest
```

### Example Commands

```bash
# Launch an interactive R session with DESeq2 loaded
docker run --rm -it -v /path/to/data:/data getwilds/deseq2:latest R

# Run an R script that uses DESeq2
docker run --rm -v /path/to/data:/data getwilds/deseq2:latest Rscript /data/my_analysis.R

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/deseq2:latest R
```

## Example Data

The image includes the `pasilla` dataset, which contains RNA-seq count data from a study on the pasilla gene in Drosophila. This dataset is useful for:

- Testing DESeq2 workflows
- Learning differential expression analysis
- Validating analysis pipelines
- Following DESeq2 tutorials and vignettes

## Integration with WILDS WDL Workflows

This Docker image provides the runtime environment for WILDS WDL modules that perform differential expression analysis. Analysis scripts (e.g., `deseq2_analysis.R`, `generate_pasilla_counts.R`) live in the [`ww-deseq2`](https://github.com/getwilds/wilds-wdl-library/tree/main/modules/ww-deseq2) and [`ww-testdata`](https://github.com/getwilds/wilds-wdl-library/tree/main/modules/ww-testdata) WDL modules rather than being baked into the image, so they can be updated without rebuilding the container.

## Security Features

The DESeq2 Docker images include:

- Built on the official Bioconductor Docker images (based on Rocker project)
- Pinned Bioconductor release version for reproducibility
- Dynamic versioning for system dependencies to ensure the latest security patches
- Minimal installation with only required dependencies

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs.txt` file in this directory, which is automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Bioconductor RELEASE_3_17 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system dependencies with version pinning
4. Installs DESeq2, pasilla example data, and related R packages
5. Sets up a working directory for data analysis

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
