# deepTools

This directory contains Docker images for [deepTools](https://deeptools.readthedocs.io/), a suite of tools for processing and analyzing high-throughput sequencing data, particularly useful for ChIP-seq, ATAC-seq, MNase-seq, and RNA-seq quality control, normalization, and visualization.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/deeptools/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/deeptools/CVEs_latest.md) )
- `3.5.6` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/deeptools/Dockerfile_3.5.6) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/deeptools/CVEs_3.5.6.md) )

## Image Details

These Docker images are built from `condaforge/miniforge3:24.7.1-2` and include:

- deepTools v3.5.6: Suite of tools for processing and visualizing deep sequencing data
- Python and scientific computing dependencies (NumPy, SciPy, matplotlib) via conda
- pysam: BAM/SAM file handling
- pyBigWig: BigWig file I/O

The images are designed to be minimal and focused on deepTools with its essential dependencies.

## Citation

If you use deepTools in your research, please cite the original authors:

```
Ramirez F, Ryan DP, Gruning B, Bhardwaj V, Kilpert F, Richter AS, Heyne S, Dundar F, Manke T.
deepTools2: a next generation web server for deep-sequencing data analysis.
Nucleic Acids Research. 2016 Jul 8; 44(W1):W160-5.
DOI: 10.1093/nar/gkw257
```

**Tool homepage:** https://deeptools.readthedocs.io/

**Publication:** https://doi.org/10.1093/nar/gkw257

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/deeptools:latest

# Or pull a specific version
docker pull getwilds/deeptools:3.5.6

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/deeptools:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/deeptools:latest

# Or pull a specific version
apptainer pull docker://getwilds/deeptools:3.5.6

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/deeptools:latest
```

### Example Commands

```bash
# Generate a normalized coverage track (bigWig) from a BAM file
docker run --rm -v /path/to/data:/data getwilds/deeptools:latest \
  bamCoverage -b /data/sample.bam -o /data/sample.bw --normalizeUsing RPKM

# Compute a matrix of scores around TSS for heatmap visualization
docker run --rm -v /path/to/data:/data getwilds/deeptools:latest \
  computeMatrix reference-point -S /data/sample.bw \
  -R /data/genes.bed -a 3000 -b 3000 -o /data/matrix.gz

# Plot a heatmap from a computed matrix
docker run --rm -v /path/to/data:/data getwilds/deeptools:latest \
  plotHeatmap -m /data/matrix.gz -o /data/heatmap.png

# Check sample correlation using multiBamSummary and plotCorrelation
docker run --rm -v /path/to/data:/data getwilds/deeptools:latest \
  bash -c "multiBamSummary bins -b /data/sample1.bam /data/sample2.bam \
  -o /data/results.npz && plotCorrelation -in /data/results.npz \
  --corMethod spearman -o /data/correlation.png"

# Using Apptainer to generate a fingerprint plot
apptainer run --bind /path/to/data:/data docker://getwilds/deeptools:latest \
  plotFingerprint -b /data/chip.bam /data/input.bam -o /data/fingerprint.png
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `condaforge/miniforge3:24.7.1-2` as the base image
2. Adds metadata labels for documentation and attribution
3. Installs deepTools v3.5.6 via mamba from the bioconda channel
4. Performs a smoke test to verify the installation
5. Cleans up conda caches to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/deeptools), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

---
