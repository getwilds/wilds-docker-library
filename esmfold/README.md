# ESMFold

This directory contains Docker images for ESMFold, an end-to-end protein structure prediction model that predicts atomic-resolution 3D protein structures directly from amino acid sequences using a large language model, without requiring multiple sequence alignments (MSAs).

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/esmfold/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/esmfold/CVEs_latest.md) )
- `2.0.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/esmfold/Dockerfile_2.0.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/esmfold/CVEs_2.0.0.md) )

## Platform Availability

ESMFold images are available for **AMD64 (x86_64) only** due to CUDA/GPU dependencies.

## Image Details

These Docker images use a multi-stage build from `nvidia/cuda:11.7.1-cudnn8-devel-ubuntu22.04` and include:

- ESMFold v2.0.0 (`fair-esm[esmfold]`): End-to-end protein structure prediction with the official `esm-fold` CLI
- OpenFold v1.0.0: Structure module dependencies compiled from source with CUDA support
- PyTorch 2.0.0 (CUDA 11.8): Deep learning framework with GPU acceleration
- Python 3.9 via Miniforge: Required by OpenFold v1.0.0

The images include the official `esm-fold` CLI from Meta's `fair-esm` package, with OpenFold compiled from source at the exact commit specified by the ESM repository. The build approach follows the proven nf-core/proteinfold pattern. Model weights (~5.5GB) are downloaded at runtime on first use and can be cached via a mounted volume.

**Note on `esm-fold` script:** The `esm-fold` CLI script is downloaded during the Docker build directly from [Meta's ESM repository](https://github.com/facebookresearch/esm/blob/main/scripts/fold.py) (MIT license), pinned to a specific commit. It is not written or maintained by WILDS/Fred Hutch OCDO. We download it because the `fair-esm` pip package does not ship the `scripts/` directory, so the CLI entry point is otherwise unavailable. The ESM repository was archived in August 2024, so the pinned commit will not change.

## Important Notes

### GPU Requirements

ESMFold requires an NVIDIA GPU with CUDA support for practical use. The model has approximately 690M parameters and requires at least 16GB of GPU VRAM for inference on typical protein sequences.

### Model Weights

Model weights (~5.5GB) are downloaded automatically on first use via the `esm-fold` CLI's `-m` flag. To avoid repeated downloads, mount a persistent directory for the model cache:

```bash
docker run --gpus all --rm \
  -v /path/to/model_cache:/models \
  -v /path/to/data:/data \
  getwilds/esmfold:latest \
  esm-fold -i /data/sequences.fasta -o /data/output/ -m /models
```

For WDL/Cromwell workflows, download the weights as a separate task and pass the directory to `esm-fold -m`.

### PyTorch Version

These images use PyTorch 2.0.0, which is the latest version compatible with the OpenFold v1.0.0 dependency stack. While newer PyTorch versions exist, they are incompatible with the pinned OpenFold commit required by ESMFold.

## Citation

If you use ESMFold in your research, please cite the original authors:

```
Lin, Z., Akin, H., Rao, R., Hie, B., Zhu, Z., Lu, W., ... & Rives, A. (2023).
Evolutionary-scale prediction of atomic-level protein structure with a language model.
Science, 379(6637), 1123-1130.
DOI: 10.1126/science.ade2574
```

**Tool homepage:** https://github.com/facebookresearch/esm

**Publication:** https://doi.org/10.1126/science.ade2574

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/esmfold:latest

# Or pull a specific version
docker pull getwilds/esmfold:2.0.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/esmfold:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/esmfold:latest

# Or pull a specific version
apptainer pull docker://getwilds/esmfold:2.0.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/esmfold:latest
```

### Example Commands

```bash
# Predict structure from a FASTA file using the esm-fold CLI
docker run --gpus all --rm -v /path/to/data:/data getwilds/esmfold:latest \
  esm-fold -i /data/sequences.fasta -o /data/predictions/ -m esmfold_v1

# Predict structure for a single sequence (write FASTA first)
docker run --gpus all --rm -v /path/to/data:/data getwilds/esmfold:latest \
  bash -c 'echo -e ">protein1\nMKTVRQERLKSIVRILERSKEPVSGAQLAEELSVSRQVIVQDIAYLRSLGYNIVATPRGYVLAGG" > /tmp/input.fasta && esm-fold -i /tmp/input.fasta -o /data/output/ -m esmfold_v1'

# Run interactively for exploratory analysis
docker run --gpus all --rm -it \
  -v /path/to/data:/data \
  getwilds/esmfold:latest \
  python

# Using Apptainer with GPU support
apptainer run --nv --bind /path/to/data:/data docker://getwilds/esmfold:latest \
  esm-fold -i /data/sequences.fasta -o /data/predictions/ -m esmfold_v1
```

## Dockerfile Structure

The Dockerfile uses a multi-stage build:

**Builder stage** (`nvidia/cuda:11.7.1-cudnn8-devel-ubuntu22.04`):
1. Installs Miniforge with Python 3.9
2. Installs ESM from GitHub and `fair-esm[esmfold]` extras
3. Installs PyTorch 2.0.0 with CUDA 11.8 support
4. Pins all dependency versions for OpenFold compatibility
5. Clones, patches, and compiles OpenFold from source at the pinned commit

**Final stage** (same CUDA base, clean):
1. Copies the `/conda` environment from the builder
2. Runs smoke tests to verify the `esm-fold` CLI and OpenFold imports

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/esmfold), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

---
