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
- A ready-to-use analysis script for standard differential expression workflows
- A test data generation script for creating STAR-format individual count files

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

#### Running DESeq2 Analysis

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

#### Generating Test Data

```bash
# Generate individual STAR-format count files using the pasilla dataset
docker run --rm -v /path/to/output:/data getwilds/deseq2:latest \
  generate_pasilla_counts.R \
  --nsamples 7 \
  --ngenes 10000 \
  --condition condition \
  --prefix /data/test_data

# Generate smaller test dataset
docker run --rm -v /path/to/output:/data getwilds/deseq2:latest \
  generate_pasilla_counts.R \
  --nsamples 4 \
  --ngenes 5000 \
  --prefix /data/small_test
```

### Script Parameters

#### DESeq2 Analysis Script (`deseq2_analysis.R`)

The included `deseq2_analysis.R` script accepts the following parameters:

- `--counts_file`: Path to input counts matrix file (required)
- `--metadata_file`: Path to sample metadata file (required)
- `--condition_column`: Column in metadata to use for comparison (default: "condition")
- `--reference_level`: Reference level for comparison (default: first alphabetically)
- `--contrast`: Contrast to use in format: condition,treatment,control (default: infer from condition_column)
- `--output_prefix`: Prefix for output files (default: "deseq2_results")

#### Test Data Generation Script (`generate_pasilla_counts.R`)

The included `generate_pasilla_counts.R` script accepts the following parameters:

- `--nsamples`: Number of samples to include (default: 7, max: 7 for pasilla dataset)
- `--ngenes`: Approximate number of genes to include (default: 10000)
- `--condition`: Name for the condition column in metadata (default: "condition")
- `--prefix`: Prefix for output files (default: "pasilla")

### Outputs

#### DESeq2 Analysis Outputs

The analysis produces the following outputs:

1. `*_all_genes.csv`: Results for all genes analyzed
2. `*_significant.csv`: Significantly differentially expressed genes (padj < 0.05)
3. `*_normalized_counts.csv`: Normalized count data
4. `*_pca.pdf`: PCA plot of samples
5. `*_volcano.pdf`: Volcano plot of differential expression results
6. `*_heatmap.pdf`: Heatmap of top differentially expressed genes

#### Test Data Generation Outputs

The test data generation produces the following outputs:

1. Individual STAR-format count files: `*_samplename.ReadsPerGene.out.tab` for each sample
   - Format matches STAR output with 4-line header (mapping statistics) followed by gene counts
   - Contains gene_id, unstranded_count, forward_strand_count, reverse_strand_count columns
2. `*_sample_names.txt`: List of sample names corresponding to the count files
3. `*_sample_conditions.txt`: List of experimental conditions for each sample
4. `*_count_files.txt`: List of generated count file names
5. `*_gene_info.txt`: Gene annotation information including gene IDs

The individual count files are designed to mimic authentic STAR `ReadsPerGene.out.tab` output, making them suitable for testing workflows that process individual sample count files before combining them into a matrix.

## Example Data

The image includes the `pasilla` dataset, which contains RNA-seq count data from a study on the pasilla gene in Drosophila. This dataset is useful for:

- Testing DESeq2 workflows
- Learning differential expression analysis
- Validating analysis pipelines
- Following DESeq2 tutorials and vignettes
- Generating customizable test datasets for workflow development
- Creating realistic STAR-format individual count files for testing count matrix combination workflows

The `generate_pasilla_counts.R` script allows you to create subsets of this data with varying numbers of samples and genes. The script generates individual count files in STAR format, which is particularly useful for testing complete RNA-seq analysis workflows that start from individual sample count files rather than pre-combined matrices.

## Integration with WILDS WDL Workflows

This Docker image is specifically designed to work with WILDS WDL modules:

- The `deseq2_analysis.R` script is used by the `ww-deseq2` module for differential expression analysis
- The `generate_pasilla_counts.R` script is used by the `ww-testdata` module to generate realistic test data
- Individual STAR-format count files can be processed by count matrix combination workflows before DESeq2 analysis

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
3. Installs DESeq2, pasilla example data, and related R packages
4. Installs system dependencies with version pinning
5. Adds the analysis and test data generation scripts and makes them executable
6. Sets up a working directory for data analysis

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
