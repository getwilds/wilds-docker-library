# ESMFold

This directory contains Docker images for ESMFold, an end-to-end protein structure prediction model that predicts atomic-resolution 3D protein structures directly from amino acid sequences using a large language model, without requiring multiple sequence alignments (MSAs).

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/esmfold/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/esmfold/CVEs_latest.md) )
- `2.0.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/esmfold/Dockerfile_2.0.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/esmfold/CVEs_2.0.0.md) )

## Platform Availability

ESMFold images are available for **AMD64 (x86_64) only** due to CUDA/GPU dependencies.

## Image Details

These Docker images are built from `python:3.11-slim` and include:

- ESMFold v2.0.0 via HuggingFace Transformers: End-to-end protein structure prediction from sequence
- PyTorch 2.6.0 (CUDA 11.8): Deep learning framework with GPU acceleration
- Biopython 1.84: Biological sequence and structure manipulation
- SciPy 1.14.1: Scientific computing utilities

The images use the HuggingFace Transformers implementation of ESMFold, which provides a simpler installation path compared to the original `fair-esm[esmfold]` package that requires OpenFold compilation. Model weights (~6-7GB) from `facebook/esmfold_v1` are baked into the image for offline-ready execution in WDL/Cromwell workflows.

## Important Notes

### GPU Requirements

ESMFold requires an NVIDIA GPU with CUDA support for practical use. The model has approximately 690M parameters and requires at least 16GB of GPU VRAM for inference on typical protein sequences.

### Model Weights

Model weights (~6-7GB) from `facebook/esmfold_v1` are pre-downloaded and baked into the image at `/opt/esmfold/model`. The container runs in offline mode (`TRANSFORMERS_OFFLINE=1`) so it never attempts network downloads at runtime, making it suitable for air-gapped or ephemeral compute environments like WDL/Cromwell workflows.

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
# Predict a protein structure from sequence using a Python script
docker run --gpus all --rm -v /path/to/data:/data getwilds/esmfold:latest \
  python -c "
from transformers import AutoTokenizer, EsmForProteinFolding
import torch

tokenizer = AutoTokenizer.from_pretrained('facebook/esmfold_v1')
model = EsmForProteinFolding.from_pretrained('facebook/esmfold_v1').cuda()
sequence = 'MKTVRQERLKSIVRILERSKEPVSGAQLAEELSVSRQVIVQDIAYLRSLGYNIVATPRGYVLAGG'
inputs = tokenizer([sequence], return_tensors='pt', add_special_tokens=False).to('cuda')
with torch.no_grad():
    output = model(**inputs)
print('Structure predicted successfully')
"

# Run with persistent model cache to avoid re-downloading weights
docker run --gpus all --rm \
  -v /path/to/cache:/root/.cache/huggingface \
  -v /path/to/data:/data \
  getwilds/esmfold:latest \
  python /data/predict_structure.py

# Run interactively for exploratory analysis
docker run --gpus all --rm -it \
  -v /path/to/data:/data \
  getwilds/esmfold:latest \
  python

# Using Apptainer with GPU support
apptainer run --nv --bind /path/to/data:/data docker://getwilds/esmfold:latest \
  python /data/predict_structure.py
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `python:3.11-slim` as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system dependencies (gcc, g++) with pinned versions for compilation support
4. Installs PyTorch 2.6.0 with CUDA 11.8 support
5. Installs HuggingFace Transformers, accelerate, biopython, and scipy
6. Runs a smoke test to verify ESMFold model classes can be imported
7. Performs cleanup via `--no-cache-dir` on all pip installs

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/esmfold), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

---
