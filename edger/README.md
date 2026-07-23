# edgeR

This directory contains Docker images for edgeR, a Bioconductor package for differential expression analysis of digital gene expression data such as RNA-seq, ChIP-seq, ATAC-seq, and similar count-based omics datasets.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/edger/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/edger/CVEs_latest.md) )
- `4.10.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/edger/Dockerfile_4.10.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/edger/CVEs_4.10.0.md) )

## Image Details

These Docker images are built from the Bioconductor base image (RELEASE_3_23) and include:

- edgeR v4.10.0: Differential expression analysis using negative binomial models with empirical Bayes estimation, exact tests, GLMs, and quasi-likelihood methods
- limma: Linear models for microarray and RNA-seq data, frequently used alongside edgeR for voom-based analyses
- ggplot2: Grammar of graphics plotting for visualization of results
- pheatmap and RColorBrewer: Heatmap visualization of expression patterns
- optparse: Command-line argument parsing for scripted workflows

The images are designed to provide a focused environment for differential expression analysis with edgeR and its most common companion tools.

## Platform Availability

**Note:** This image is only built for **linux/amd64** architecture. edgeR and its C++ dependencies have compilation issues on ARM64 platforms.

## Citation

If you use edgeR in your research, please cite the original authors:

```
Robinson MD, McCarthy DJ, Smyth GK (2010). edgeR: a Bioconductor package for
differential expression analysis of digital gene expression data.
Bioinformatics, 26(1), 139-140. https://doi.org/10.1093/bioinformatics/btp616

McCarthy DJ, Chen Y, Smyth GK (2012). Differential expression analysis of
multifactor RNA-Seq experiments with respect to biological variation.
Nucleic Acids Research, 40(10), 4288-4297. https://doi.org/10.1093/nar/gks042

Chen Y, Lun ATL, Smyth GK (2016). From reads to genes to pathways: differential
expression analysis of RNA-Seq experiments using Rsubread and the edgeR
quasi-likelihood pipeline. F1000Research, 5, 1438.
https://doi.org/10.12688/f1000research.8987.2
```

**Tool homepage:** https://bioconductor.org/packages/release/bioc/html/edgeR.html

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/edger:latest

# Or pull a specific version
docker pull getwilds/edger:4.10.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/edger:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/edger:latest

# Or pull a specific version
apptainer pull docker://getwilds/edger:4.10.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/edger:latest
```

### Example Commands

```bash
# Launch an interactive R session with edgeR loaded
docker run --rm -it -v /path/to/data:/data getwilds/edger:latest R

# Run an R script that performs edgeR differential expression analysis
docker run --rm -v /path/to/data:/data getwilds/edger:latest \
  Rscript /data/edger_analysis.R

# Run a quick inline edgeR analysis on count data
docker run --rm -v /path/to/data:/data getwilds/edger:latest R -e "
  library(edgeR)
  counts <- read.table('/data/counts.txt', header=TRUE, row.names=1)
  group <- factor(c('control','control','treatment','treatment'))
  dge <- DGEList(counts=counts, group=group)
  dge <- calcNormFactors(dge)
  dge <- estimateDisp(dge)
  et <- exactTest(dge)
  write.csv(topTags(et, n=Inf), '/data/edger_results.csv')
"

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/edger:latest \
  Rscript /data/edger_analysis.R

# Or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data edger_latest.sif \
  Rscript /data/edger_analysis.R
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Bioconductor RELEASE_3_23 as the base image
2. Adds metadata labels for documentation and attribution
3. Sets R library paths to prevent host library contamination in Apptainer
4. Installs edgeR, limma, and visualization packages via BiocManager
5. Runs a smoke test to confirm edgeR loads and reports its version
6. Sets `/data` as the default working directory

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/edger), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
