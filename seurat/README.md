# Seurat

This directory contains Docker images for Seurat, an R package for single-cell RNA-seq data analysis.

## Available Versions

- `latest`: The most up-to-date stable version (currently Seurat v5.2.1 from Bioconductor 3.21)
- `5.2.1`: Seurat v5.2.1 from Bioconductor 3.21

## Image Details

These Docker images are built from the Bioconductor base image and include:

- Seurat v5.2.1: A package for single-cell RNA-seq data quality control, analysis, and exploration
- glmGamPoi: For fast negative binomial regression in SCTransform normalization
- ggplot2 & patchwork: For visualization and plot composition
- dplyr: For data manipulation
- optparse: For command-line interface
- A script that performs standard gene expression scRNA-seq processing (see below)

## Usage

### Docker

```bash
docker pull getwilds/seurat:latest
# or
docker pull getwilds/seurat:5.2.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/seurat:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/seurat:latest
# or
apptainer pull docker://getwilds/seurat:5.2.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/seurat:latest
```

### Example Commands

#### Running Seurat Analysis

```bash
# Running Seurat analysis with default parameters
docker run --rm -v /path/to/data:/data getwilds/seurat:latest Rscript /usr/local/bin/seurat_analysis.R \
  --input_h5=/data/sample_filtered_feature_bc_matrix.h5 \
  --sample_name=my_sample \
  --output_prefix=/data/results/my_sample

# Specifying QC thresholds and clustering resolution
docker run --rm -v /path/to/data:/data getwilds/seurat:latest Rscript /usr/local/bin/seurat_analysis.R \
  --input_h5=/data/sample_filtered_feature_bc_matrix.h5 \
  --sample_name=my_sample \
  --min_cells=5 \
  --min_features=500 \
  --max_percent_mt=20.0 \
  --resolution=0.8 \
  --ram_gb=16 \
  --output_prefix=/data/results/my_sample

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/seurat:latest Rscript /usr/local/bin/seurat_analysis.R \
  --input_h5=/data/sample_filtered_feature_bc_matrix.h5 \
  --sample_name=my_sample \
  --output_prefix=/data/results/my_sample
```

### Script Parameters

#### Seurat Analysis Script (`seurat_analysis.R`)

The included `seurat_analysis.R` script accepts the following parameters:

- `--input_h5`: Path to Cell Ranger filtered feature barcode matrix `.h5` file (required)
- `--sample_name`: Sample name used for project labeling and default output naming (required)
- `--min_cells`: Minimum number of cells a gene must be detected in to be retained (default: 3)
- `--min_features`: Minimum number of features (genes) a cell must have to be retained (default: 200)
- `--max_percent_mt`: Maximum percent mitochondrial reads allowed per cell (default: 10.0)
- `--resolution`: Louvain clustering resolution; higher values produce more clusters (default: 0.5)
- `--output_prefix`: Prefix for all output files; defaults to `--sample_name` if not provided
- `--ram_gb`: Maximum RAM the script may use in GB, controls `future.globals.maxSize` for parallel operations (default: 4)

### Outputs

The analysis produces the following outputs:

1. `*_qc.png`: Violin plots of QC metrics (nFeature_RNA, nCount_RNA, percent.mt) before filtering
2. `*_umap.png`: UMAP plot colored and labeled by Louvain cluster
3. `*_top30_markers.csv`: Top 30 marker genes per cluster ranked by average log2 fold-change
4. `*_heatmap.png`: Heatmap of the top 8 marker genes per cluster
5. `*.rds`: Serialized Seurat object with all analysis results embedded

## Analysis Workflow

The `seurat_analysis.R` script performs the following steps:

1. **Load data**: Reads a Cell Ranger `.h5` matrix file using `Read10X_h5()`
2. **QC filtering**: Computes mitochondrial percentage, plots QC metrics, and removes low-quality cells
3. **Normalization**: Runs SCTransform with `glmGamPoi` for fast negative binomial regression and mitochondrial percent regression
4. **Dimensionality reduction**: Runs PCA (30 PCs) followed by UMAP embedding
5. **Clustering**: Builds a shared nearest-neighbor graph and finds Louvain clusters at the specified resolution
6. **Marker genes**: Identifies positive marker genes per cluster using Wilcoxon rank-sum test
7. **Save results**: Writes plots, marker tables, and the Seurat object to disk

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Bioconductor RELEASE_3_21 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system dependencies (HDF5, FFTW3, GSL) with version pinning
4. Sets R library paths to avoid host contamination in Apptainer
5. Installs Seurat, glmGamPoi, and supporting R packages
6. Copies the analysis script and makes it executable
7. Sets up a working directory for data analysis

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs.txt` file in this directory, which is automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
