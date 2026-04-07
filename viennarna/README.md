# ViennaRNA

This directory contains Docker images for [ViennaRNA](https://www.tbi.univie.ac.at/RNA/), a widely used package for RNA secondary structure prediction, comparison, and analysis.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/viennarna/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/viennarna/CVEs_latest.md) )
- `2.7.2` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/viennarna/Dockerfile_2.7.2) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/viennarna/CVEs_2.7.2.md) )

## Image Details

These Docker images are built from `condaforge/miniforge3:24.7.1-2` and include:

- ViennaRNA v2.7.2: A comprehensive suite of tools for RNA secondary structure prediction, partition function calculations, suboptimal structure enumeration, RNA-RNA interaction prediction, and sequence design
- Python and Perl bindings for programmatic access to the ViennaRNA library

The images are designed to be minimal and focused on ViennaRNA with its essential dependencies.

## Citation

If you use ViennaRNA in your research, please cite the original authors:

```
Lorenz, R., Bernhart, S.H., Höner zu Siederdissen, C., Tafer, H., Flamm, C.,
Stadler, P.F. and Hofacker, I.L. (2011). ViennaRNA Package 2.0.
Algorithms for Molecular Biology, 6:26.
https://doi.org/10.1186/1748-7188-6-26
```

**Tool homepage:** https://www.tbi.univie.ac.at/RNA/

**GitHub:** https://github.com/ViennaRNA/ViennaRNA

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/viennarna:latest

# Or pull a specific version
docker pull getwilds/viennarna:2.7.2

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/viennarna:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/viennarna:latest

# Or pull a specific version
apptainer pull docker://getwilds/viennarna:2.7.2

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/viennarna:latest
```

### Example Commands

```bash
# Predict minimum free energy (MFE) structure of an RNA sequence
echo "GGGAAAUCC" | docker run --rm -i getwilds/viennarna:latest RNAfold

# Predict MFE structure from a FASTA file
docker run --rm -v /path/to/data:/data getwilds/viennarna:latest \
  RNAfold --infile=/data/sequences.fa --outfile=/data/structures.txt

# Compute suboptimal structures within 5 kcal/mol of MFE
echo "GGGAAAUCC" | docker run --rm -i getwilds/viennarna:latest \
  RNAsubopt -e 5

# Predict consensus structure from a multiple sequence alignment
docker run --rm -v /path/to/data:/data getwilds/viennarna:latest \
  RNAalifold /data/alignment.aln

# Design a sequence that folds into a target structure (inverse folding)
echo "(((...)))" | docker run --rm -i getwilds/viennarna:latest RNAinverse

# Alternatively using Apptainer
echo "GGGAAAUCC" | apptainer run docker://getwilds/viennarna:latest RNAfold
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `condaforge/miniforge3:24.7.1-2` as the base image
2. Adds metadata labels for documentation and attribution
3. Installs ViennaRNA v2.7.2 via mamba from the bioconda channel
4. Runs smoke tests to verify RNAfold, RNAalifold, and RNAeval are functional
5. Performs cleanup with `mamba clean -afy` to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/viennarna), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

---
