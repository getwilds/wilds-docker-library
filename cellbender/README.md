# CellBender

This directory contains Docker images for CellBender, a tool for removing technical artifacts (ambient RNA and barcode swapping) from droplet-based single-cell and single-nucleus RNA sequencing count matrices.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/cellbender/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/cellbender/CVEs_latest.md) )
- `0.3.2` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/cellbender/Dockerfile_0.3.2) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/cellbender/CVEs_0.3.2.md) )

## Image Details

These Docker images are built from Python 3.11 slim and include:

- CellBender v0.3.2: Removes ambient RNA and barcode swapping artifacts from scRNA-seq/snRNA-seq count matrices using a deep generative model
- PyTorch v2.0.1 (CUDA-enabled): Pinned to 2.0.1 to avoid a `torch.save` weakref serialization bug present in later PyTorch versions that causes CellBender checkpointing to fail; provides GPU acceleration when run on a machine with compatible NVIDIA drivers and the `--cuda` flag; falls back to CPU automatically when no GPU is available
- NumPy <2.0: Pinned to the 1.x series to match the ABI that PyTorch 2.0.1 was compiled against; NumPy 2.x breaks torch tensor-to-array conversion at runtime
- PyTables/HDF5: Required for reading and writing `.h5` count matrix files

The images are designed to be minimal and focused on CellBender with its essential dependencies.

## Citation

If you use CellBender in your research, please cite the original authors:

```
Fleming, S.J., Chaffin, M.D., Arduini, A., Akkad, A.D., Banks, E., Marioni, J.C.,
Philippakis, A.A., Ellinor, P.T., & Babadi, M. (2023). Unsupervised removal of
systematic background noise from droplet-based single-cell experiments using CellBender.
Nature Methods, 20, 1323-1335. https://doi.org/10.1038/s41592-023-01943-7
```

**Tool homepage:** https://github.com/broadinstitute/CellBender

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/cellbender:latest

# Or pull a specific version
docker pull getwilds/cellbender:0.3.2

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/cellbender:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/cellbender:latest

# Or pull a specific version
apptainer pull docker://getwilds/cellbender:0.3.2

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/cellbender:latest
```

### Example Commands

```bash
# Remove background from a CellRanger output directory (CPU)
docker run --rm -v /path/to/data:/data getwilds/cellbender:latest \
  cellbender remove-background \
  --input /data/raw_feature_bc_matrix.h5 \
  --output /data/cellbender_output.h5

# Remove background with GPU acceleration (requires NVIDIA runtime)
docker run --rm --gpus all -v /path/to/data:/data getwilds/cellbender:latest \
  cellbender remove-background \
  --input /data/raw_feature_bc_matrix.h5 \
  --output /data/cellbender_output.h5 \
  --cuda

# Remove background with custom parameters (expected cells and droplets)
docker run --rm -v /path/to/data:/data getwilds/cellbender:latest \
  cellbender remove-background \
  --input /data/raw_feature_bc_matrix.h5 \
  --output /data/cellbender_output.h5 \
  --expected-cells 5000 \
  --total-droplets-included 15000 \
  --fpr 0.01 \
  --epochs 150

# Using Apptainer with a local SIF file
apptainer run --bind /path/to/data:/data cellbender_latest.sif \
  cellbender remove-background \
  --input /data/raw_feature_bc_matrix.h5 \
  --output /data/cellbender_output.h5
```

## Important Notes

### GPU support

The PyTorch included in this image is built with CUDA support. On machines with an NVIDIA GPU and compatible drivers, pass `--gpus all` to Docker (or `--nv` to Apptainer) and add the `--cuda` flag to the `cellbender` command. CellBender will automatically fall back to CPU if no GPU is detected.

### Output files

CellBender produces an `.h5` output file containing corrected counts and latent variables. The filtered count matrix can be loaded directly into Scanpy (`sc.read_10x_h5`) or converted for use in Seurat.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Python 3.11 slim as the base image
2. Adds metadata labels for documentation and attribution
3. Installs HDF5 system libraries (`libhdf5-dev`) required by the PyTables dependency
4. Installs PyTorch v2.0.1 and CellBender v0.3.2 via pip with pinned torch version to avoid a checkpoint serialization bug in later PyTorch releases
5. Runs `cellbender --version` as a smoke test to verify the install
6. Uses `--no-cache-dir` and apt list cleanup to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/cellbender), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
