# PRS-CSx

This directory contains Docker images for PRS-CSx, a Python command-line tool that integrates GWAS summary statistics and external LD reference panels from multiple populations to improve cross-population polygenic prediction. Posterior SNP effect sizes are inferred under coupled continuous shrinkage (CS) priors across populations.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/prscsx/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/prscsx/CVEs_latest.md) )
- `1.1.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/prscsx/Dockerfile_1.1.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/prscsx/CVEs_1.1.0.md) )

**Note on versioning:** The upstream `v1.1.0` tag predates a May 2024 fix for newer SciPy releases and a Nov 2024 feature that writes all posterior samples (`--write_pst`). Both images therefore bundle upstream commit [`bdf5f30`](https://github.com/getian107/PRScsx/commit/bdf5f30e5e5e9aa9f357ec31b4d0eca7d155e9a8) (post-v1.1.0, which upstream still labels 1.1.0) rather than the tag itself.

## Platform Availability

These images are available for both `linux/amd64` and `linux/arm64`.

## Image Details

These Docker images are built from `python:3.12-slim` and include:

- PRS-CSx (upstream commit `bdf5f30`): the `PRScsx.py` script and its modules, installed in `/opt/PRScsx` and available on the `PATH` as `PRScsx.py`
- numpy 1.26.4: numerical arrays (upstream recommends NumPy 1.x)
- scipy 1.11.4: linear algebra and statistics routines used by the MCMC sampler
- h5py 3.12.1: reads the HDF5 LD reference panel blocks

The Python package versions follow the combination recommended in the upstream README (h5py is bumped from 3.10 to 3.12 because earlier releases have no ARM64 wheels). Git is used only at build time and is removed from the final image. The LD reference panels and SNP information files are **not** included (each panel is 4-7 GB); download them from the [upstream repository](https://github.com/getian107/PRScsx#getting-started) and mount them into the container.

## Citation

If you use PRS-CSx in your research, please cite the original authors:

```
Ruan Y, Lin YF, Feng YCA, Chen CY, Lam M, Guo Z, Stanley Global Asia Initiatives, He L, Sawa A, Martin AR, Qin S, Huang H, Ge T. (2022).
Improving polygenic prediction in ancestrally diverse populations. Nature Genetics, 54:573-580.
https://doi.org/10.1038/s41588-022-01054-7
```

**Tool homepage:** https://github.com/getian107/PRScsx

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/prscsx:latest

# Or pull a specific version
docker pull getwilds/prscsx:1.1.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/prscsx:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/prscsx:latest

# Or pull a specific version
apptainer pull docker://getwilds/prscsx:1.1.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/prscsx:latest
```

### Example Commands

```bash
# Example 1: Print the list of command-line options
docker run --rm getwilds/prscsx:latest PRScsx.py --help

# Example 2: Run PRS-CSx on chromosome 22 with two GWAS (EUR and EAS), fixing phi
docker run --rm \
  -v /path/to/ref:/ref -v /path/to/data:/data \
  getwilds/prscsx:latest \
  PRScsx.py \
    --ref_dir=/ref \
    --bim_prefix=/data/target \
    --sst_file=/data/eur_sumstats.txt,/data/eas_sumstats.txt \
    --n_gwas=200000,100000 \
    --pop=EUR,EAS \
    --chrom=22 \
    --phi=1e-2 \
    --out_dir=/data/results \
    --out_name=trait

# Example 3: Also write meta-analyzed effect sizes, with a fixed seed and a limited thread count
docker run --rm \
  -e MKL_NUM_THREADS=4 -e NUMEXPR_NUM_THREADS=4 -e OMP_NUM_THREADS=4 \
  -v /path/to/ref:/ref -v /path/to/data:/data \
  getwilds/prscsx:latest \
  PRScsx.py \
    --ref_dir=/ref --bim_prefix=/data/target \
    --sst_file=/data/eur_sumstats.txt,/data/eas_sumstats.txt \
    --n_gwas=200000,100000 --pop=EUR,EAS \
    --meta=True --seed=42 \
    --out_dir=/data/results --out_name=trait

# Alternatively using Apptainer
apptainer run \
  --bind /path/to/ref:/ref --bind /path/to/data:/data \
  docker://getwilds/prscsx:latest \
  PRScsx.py --ref_dir=/ref --bim_prefix=/data/target \
    --sst_file=/data/eur_sumstats.txt,/data/eas_sumstats.txt \
    --n_gwas=200000,100000 --pop=EUR,EAS \
    --chrom=22 --out_dir=/data/results --out_name=trait

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/ref:/ref --bind /path/to/data:/data prscsx_latest.sif \
  PRScsx.py --help
```

## Important Notes

### Reference panels

`--ref_dir` must contain the SNP information file (e.g. `snpinfo_mult_1kg_hm3` or `snpinfo_mult_ukbb_hm3`) and the `ldblk_*` directories for each population being analyzed. These must be downloaded separately from the upstream project.

### Thread usage

PRS-CSx relies on numpy/scipy, which use all available cores by default. On shared nodes, limit threads with `MKL_NUM_THREADS`, `NUMEXPR_NUM_THREADS`, and `OMP_NUM_THREADS`, as shown in Example 3.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `python:3.12-slim` as the base image
2. Adds metadata labels for documentation and attribution
3. Installs git (pinned) for the build-time clone
4. Installs numpy, scipy, and h5py with pinned versions
5. Clones PRS-CSx at a pinned commit, removes git metadata and bundled test data, and links `PRScsx.py` onto the `PATH`
6. Removes git and apt lists to minimize image size
7. Runs a smoke test that imports the dependencies and invokes `PRScsx.py --help`

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/prscsx), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
