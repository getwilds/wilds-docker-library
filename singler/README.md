# SingleR

This directory contains Docker images for SingleR, a Bioconductor package for automatic cell type annotation of single-cell RNA-seq data by comparing expression profiles against labeled reference datasets.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/singler/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/singler/CVEs_latest.md) )
- `2.14.1` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/singler/Dockerfile_2.14.1) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/singler/CVEs_2.14.1.md) )

## Image Details

These Docker images are built from the Bioconductor base image (RELEASE_3_23) and include:

- SingleR v2.14.1: Unbiased cell type recognition for single-cell RNA-seq data, leveraging reference transcriptomic datasets of pure cell types to infer the cell of origin of each single cell independently
- scran: Clustering and marker gene identification, commonly used to prepare data for SingleR annotation
- celldex: Curated collection of reference transcriptomic datasets used as SingleR annotation references

### Bundled Reference Data

The `celldex` `HumanPrimaryCellAtlasData` reference is downloaded at build time and baked into the image's cache, both the gene-symbol variant and the Ensembl-ID variant (`ensembl = TRUE`, which also bundles the matching EnsDb annotation package). Calling `celldex::HumanPrimaryCellAtlasData()` or `celldex::HumanPrimaryCellAtlasData(ensembl = TRUE)` inside the container returns the cached data with no network access required, which makes the image usable on air-gapped HPC nodes.

`celldex` 2.x fetches references through the `gypsum` backend, so the cache location is pinned with `GYPSUM_CACHE_DIR=/opt/hubcache/gypsum` (the Ensembl variant's EnsDb package uses AnnotationHub, pinned alongside it with `ANNOTATION_HUB_CACHE`). These are set as image environment variables and, as a fallback for runtimes that remap `$HOME`, backfilled by a snippet in `Rprofile.site` that only sets each variable if the caller has not already set it.

**Read-only filesystems:** `gypsum` and AnnotationHub both acquire a write lock inside their cache directory on every fetch, even when the requested data is already cached (AnnotationHub also locks its metadata SQLite DB). If you run this image with a read-only root filesystem (Apptainer, many HPC batch systems), pointing the cache variables at the baked-in `/opt/hubcache` paths will fail with `Cannot open lock file: Read-only file system`. Copy the caches to a writable location first and repoint the variables:

```bash
for c in gypsum annotationhub experimenthub; do
  mkdir -p "$PWD/$c-cache"
  cp -r "/opt/hubcache/$c/." "$PWD/$c-cache/"
done
export GYPSUM_CACHE_DIR="$PWD/gypsum-cache"
export ANNOTATION_HUB_CACHE="$PWD/annotationhub-cache"
export EXPERIMENT_HUB_CACHE="$PWD/experimenthub-cache"
export ANNOTATION_HUB_LOCAL=TRUE  # work from the local cache, skip the online metadata refresh
```

The [`ww-singler`](https://github.com/getwilds/wilds-wdl-library/tree/main/modules/ww-singler) WDL module does this automatically.

Other celldex references (for example `MonacoImmuneData` or `BlueprintEncodeData`) are not bundled and will be downloaded on first use, which requires network access.

The images are designed to provide a focused environment for single-cell RNA-seq cell type annotation with SingleR and its most common companion tools.

## Platform Availability

**Note:** This image is only built for **linux/amd64** architecture. SingleR and its C++ dependencies have compilation issues on ARM64 platforms.

## Citation

If you use SingleR in your research, please cite the original authors:

```
Aran D, Looney AP, Liu L, Wu E, Fong V, Hsu A, Chak S, et al. (2019).
Reference-based analysis of lung single-cell sequencing reveals a
transitional profibrotic macrophage. Nature Immunology, 20(2), 163-172.
https://doi.org/10.1038/s41590-018-0276-y
```

**Tool homepage:** https://bioconductor.org/packages/release/bioc/html/SingleR.html

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/singler:latest

# Or pull a specific version
docker pull getwilds/singler:2.14.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/singler:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/singler:latest

# Or pull a specific version
apptainer pull docker://getwilds/singler:2.14.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/singler:latest
```

### Example Commands

```bash
# Launch an interactive R session with SingleR loaded
docker run --rm -it -v /path/to/data:/data getwilds/singler:latest R

# Run an R script that performs a SingleR annotation workflow
docker run --rm -v /path/to/data:/data getwilds/singler:latest \
  Rscript /data/singler_analysis.R

# Run a quick inline SingleR annotation using the bundled celldex reference.
# HumanPrimaryCellAtlasData() loads from the in-image cache, so this works
# with no network access (for example on an air-gapped HPC node).
docker run --rm -v /path/to/data:/data getwilds/singler:latest R -e "
  library(SingleR)
  library(celldex)
  sce <- readRDS('/data/sce.rds')
  ref <- celldex::HumanPrimaryCellAtlasData()
  pred <- SingleR(test = sce, ref = ref, labels = ref\$label.main)
  saveRDS(pred, '/data/singler_predictions.rds')
  write.csv(as.data.frame(pred[, 1:4]), '/data/singler_predictions.csv')
"

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/singler:latest \
  Rscript /data/singler_analysis.R

# Or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data singler_latest.sif \
  Rscript /data/singler_analysis.R
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Bioconductor RELEASE_3_23 as the base image
2. Adds metadata labels for documentation and attribution
3. Sets R library paths to prevent host library contamination in Apptainer
4. Pins the gypsum and AnnotationHub caches under `/opt/hubcache` so bundled data is found regardless of `$HOME`
5. Installs SingleR, scran, and celldex via BiocManager
6. Runs a smoke test to confirm SingleR loads and reports its version
7. Pre-fetches the `HumanPrimaryCellAtlasData` celldex reference (gene-symbol and Ensembl-ID variants) into the image cache, asserts the cache resolved to the pinned path and the assay files landed on disk, and makes the cache world-readable
8. Sets `/data` as the default working directory

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/singler), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
