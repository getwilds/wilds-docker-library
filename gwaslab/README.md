# GWASLab

This directory contains Docker images for GWASLab, a Python-based toolkit for loading, processing, quality controlling, visualizing, and analyzing genome-wide association study (GWAS) summary statistics.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/gwaslab/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/gwaslab/CVEs_latest.md) )
- `4.2.1` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/gwaslab/Dockerfile_4.2.1) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/gwaslab/CVEs_4.2.1.md) )

## Image Details

These Docker images are built from the Python 3.12 slim image and include:

- GWASLab v4.2.1: A toolkit for standardizing, harmonizing, quality controlling, and visualizing GWAS summary statistics
- Its full dependency stack (pandas, numpy, scipy, matplotlib, seaborn, pysam, polars, and others), installed automatically via pip

The images are designed to be minimal and focused on GWASLab with its essential dependencies.

## Citation

If you use GWASLab in your research, please cite the original authors:

```
He, Y., Koiko, M., Shimmori, Y., Kamatani, Y. (2023). GWASLab: a Python package
for processing and visualizing GWAS summary statistics. Preprint at Jxiv, 2023-5.
https://doi.org/10.51094/jxiv.370
```

**Tool homepage:** https://cloufield.github.io/gwaslab/

**Source repository:** https://github.com/Cloufield/gwaslab

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/gwaslab:latest

# Or pull a specific version
docker pull getwilds/gwaslab:4.2.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/gwaslab:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/gwaslab:latest

# Or pull a specific version
apptainer pull docker://getwilds/gwaslab:4.2.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/gwaslab:latest
```

### Example Commands

```bash
# Example 1: Check the installed GWASLab version
docker run --rm getwilds/gwaslab:latest \
  python -c "import gwaslab as gl; print(gl.__version__)"

# Example 2: Load and standardize a sumstats file, then save the QC'd result
docker run --rm -v /path/to/data:/data getwilds/gwaslab:latest \
  python -c "
import gwaslab as gl
sumstats = gl.Sumstats('/data/sumstats.tsv.gz',
                        snpid='SNP', chrom='CHR', pos='POS',
                        ea='EA', nea='NEA', beta='BETA', se='SE',
                        p='P', build='38')
sumstats.basic_check()
sumstats.to_csv('/data/sumstats_qc.tsv.gz', sep='\t')
"

# Example 3: Generate a Manhattan and QQ plot from a script mounted into the container
docker run --rm -v /path/to/data:/data -v /path/to/script:/script getwilds/gwaslab:latest \
  python /script/plot_manhattan.py

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/gwaslab:latest \
  python -c "import gwaslab as gl; print(gl.__version__)"

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data gwaslab_latest.sif \
  python /script/plot_manhattan.py
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Python 3.12 slim as the base image
2. Adds metadata labels for documentation and attribution
3. Temporarily installs `build-essential` so pip can compile dependencies without prebuilt wheels for the target platform (e.g. scikit-allel on arm64)
4. Installs GWASLab and its dependencies via pip with a pinned version
5. Verifies the installation by importing the package and printing its version
6. Removes `build-essential` and apt caches to keep the image minimal

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/gwaslab), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
