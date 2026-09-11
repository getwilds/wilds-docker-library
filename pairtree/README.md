# Pairtree

This directory contains Docker images for Pairtree, a tool for reconstructing cancer evolutionary history from multi-sample bulk DNA sequencing data and analyzing intratumor genetic heterogeneity.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/pairtree/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/pairtree/CVEs_latest.md) )
- `1.0.1` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/pairtree/Dockerfile_1.0.1) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/pairtree/CVEs_1.0.1.md) )

## Image Details

These Docker images are built from the Conda Forge Miniforge base image and include:

- Pairtree v1.0.1: Reconstructs clone trees from mutation read counts across multiple tumor samples, and produces interactive HTML visualizations of posterior tree uncertainty
- projectppm: A C library (built from source) that Pairtree uses to fit subclone frequencies
- numpy, scipy, scikit-learn, numba, tqdm: Core scientific computing dependencies
- plotly, colorlover: Used by Pairtree's `plottree` script to render interactive visualizations

The images are designed to be minimal and focused on Pairtree with its essential dependencies. Pairtree is distributed only as a git repository (no PyPI or conda package exists), so `bin/pairtree` and `bin/plottree` are added directly to `PATH`.

## Citation

If you use Pairtree in your research, please cite the original authors:

```
Wintersinger, J.A., Dobson, S.M., Kulman, E., Stein, L.D., Dick, J.E., Morris, Q. (2022).
Reconstructing complex cancer evolutionary histories from multiple bulk DNA samples
using Pairtree. Blood Cancer Discovery, 3(3), 208-219.
https://doi.org/10.1158/2643-3230.BCD-21-0092
```

**Tool homepage:** https://github.com/morrislab/pairtree

Note: This Docker image is simply a containerized version of the tool. All credit for the tool's development goes to the original authors.

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/pairtree:latest

# Or pull a specific version
docker pull getwilds/pairtree:1.0.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/pairtree:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/pairtree:latest

# Or pull a specific version
apptainer pull docker://getwilds/pairtree:1.0.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/pairtree:latest
```

### Example Commands

```bash
# Build clone trees from a .ssm mutation file and .params.json sample metadata
docker run --rm -v /path/to/data:/data getwilds/pairtree:latest \
  pairtree --params /data/example.params.json /data/example.ssm /data/example.results.npz

# Generate an interactive HTML visualization of the sampled trees
docker run --rm -v /path/to/data:/data getwilds/pairtree:latest \
  plottree --runid example /data/example.ssm /data/example.params.json \
  /data/example.results.npz /data/example.results.html

# Limit parallelism and set a random seed for reproducibility
docker run --rm -v /path/to/data:/data getwilds/pairtree:latest \
  pairtree --seed 1 --parallel 4 --params /data/example.params.json \
  /data/example.ssm /data/example.results.npz

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/pairtree:latest \
  pairtree --params /data/example.params.json /data/example.ssm /data/example.results.npz

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data pairtree_latest.sif \
  plottree --runid example /data/example.ssm /data/example.params.json \
  /data/example.results.npz /data/example.results.html
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses the Conda Forge Miniforge image (Ubuntu 24.04-based) as the base image
2. Adds metadata labels for documentation and attribution
3. Installs `build-essential` and `git` with pinned versions via `apt-cache policy`
4. Installs Pairtree's Python dependencies (numpy, scipy, scikit-learn, numba, tqdm) plus the plotting extras (plotly, colorlover) via mamba
5. Clones the Pairtree v1.0.1 tag and the projectppm repository (pinned to a specific commit) into `/opt/pairtree`
6. Compiles the projectppm C library that Pairtree uses for subclone frequency fitting
7. Adds `/opt/pairtree/bin` to `PATH` so `pairtree` and `plottree` are directly callable
8. Runs a smoke test (`pairtree --help`) to confirm the install
9. Cleans up conda caches, apt lists, and git metadata to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/pairtree), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
