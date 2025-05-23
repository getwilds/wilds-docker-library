# DESeq2

This directory contains Docker images for DESeq2, a Bioconductor package for differential expression analysis of RNA-seq count data.

## Available Versions

- `latest`: The most up-to-date stable version (currently DESeq2 v1.40.2 from Bioconductor 3.17)
- `1.40.2`: DESeq2 v1.40.2 from Bioconductor 3.17

## Image Details

These Docker images are built from the Bioconductor base image and include:

- DESeq2 v1.40.2: A package for differential expression analysis of RNA-seq count data
- apeglm: For LFC shrinkage estimation
- pheatmap & RColorBrewer: For visualization of differential expression results
- optparse, ggplot2, dplyr: For command-line interface and data processing
- A ready-to-use analysis script for standard differential expression workflows

The images are designed to provide a comprehensive environment for RNA-seq differential expression analysis with DESeq2 methodology.

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
# Running DESeq2 analysis with default parameters
docker run --rm -v /path/to/data:/data getwilds/deseq2:latest Rscript /deseq2_analysis.R \
  --counts_file=/data/counts_matrix.txt \
  --metadata_file=/data/sample_metadata.txt \
  --output_prefix=/data/results

# Specifying condition column and reference level
docker run --rm -v /path/to/data:/data getwilds/deseq2:latest Rscript /deseq2_analysis.R \
  --counts_file=/data/counts_matrix.txt \
  --metadata_file=/data/sample_metadata.txt \
  --condition_column=treatment \
  --reference_level=control \
  --output_prefix=/data/results

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/deseq2:latest Rscript /deseq2_analysis.R \
  --counts_file=/data/counts_matrix.txt \
  --metadata_file=/data/sample_metadata.txt \
  --output_prefix=/data/results
```

### Script Parameters

The included `deseq2_analysis.R` script accepts the following parameters:

- `--counts_file`: Path to input counts matrix file (required)
- `--metadata_file`: Path to sample metadata file (required)
- `--condition_column`: Column in metadata to use for comparison (default: "condition")
- `--reference_level`: Reference level for comparison (default: first alphabetically)
- `--contrast`: Contrast to use in format: condition,treatment,control (default: infer from condition_column)
- `--output_prefix`: Prefix for output files (default: "deseq2_results")

### Outputs

The analysis produces the following outputs:

1. `*_all_genes.csv`: Results for all genes analyzed
2. `*_significant.csv`: Significantly differentially expressed genes (padj < 0.05)
3. `*_normalized_counts.csv`: Normalized count data
4. `*_pca.pdf`: PCA plot of samples
5. `*_volcano.pdf`: Volcano plot of differential expression results
6. `*_heatmap.pdf`: Heatmap of top differentially expressed genes

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
3. Installs DESeq2 and related R packages
4. Installs system dependencies with version pinning
5. Adds the analysis script and makes it executable
6. Sets up a working directory for data analysis

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
