# Clair3

This directory contains Docker images for Clair3, a germline small variant caller optimized for long-read sequencing data (Oxford Nanopore and PacBio HiFi) that identifies SNPs and indels using a pileup-plus-full-alignment approach with PyTorch-based deep learning models.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/clair3/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/clair3/CVEs_latest.md) )
- `2.0.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/clair3/Dockerfile_2.0.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/clair3/CVEs_2.0.0.md) )

## Image Details

These Docker images are built from `nvidia/cuda:12.6.3-runtime-ubuntu24.04` with Miniforge installed on top, and include:

- Clair3 v2.0.0: Germline small variant caller for long-read sequencing (ONT, PacBio HiFi), built from source
- samtools: BAM/CRAM file processing
- whatshap: Read-based phasing support
- PyTorch with CUDA 12.6 support: GPU-accelerated deep learning inference (pass `--use_gpu` to enable)
- PyPy 3.11 v7.3.20: Preprocessing acceleration
- longphase v1.7.3: Long-read phasing

The images support both CPU and GPU execution — GPU mode is opt-in via the `--use_gpu` flag, so the image works in CPU-only environments without any changes. Pre-trained sequencing models are not bundled in the image; see Example Commands below for how to download and mount them at runtime.

## Citation

If you use Clair3 in your research, please cite the original authors:

```
Zheng, Z., Li, S., Su, J., Leung, A.W.S., Lam, T.W., & Luo, R. (2022).
Symphonizing pileup and full-alignment for deep learning-based long-read variant calling.
Nature Computational Science, 2, 797–803.
https://doi.org/10.1038/s43588-022-00387-x
```

**Tool homepage:** https://github.com/HKU-BAL/Clair3

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/clair3:latest

# Or pull a specific version
docker pull getwilds/clair3:2.0.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/clair3:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/clair3:latest

# Or pull a specific version
apptainer pull docker://getwilds/clair3:2.0.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/clair3:latest
```

### Example Commands

Clair3 requires pre-trained models to call variants. Models are downloaded separately from https://github.com/HKU-BAL/Clair3#pre-trained-models and mounted into the container at runtime.

```bash
# Download a pre-trained model (e.g., for ONT R10.4.1 Q20+ data)
wget -q https://www.bio8.cs.hku.hk/clair3/clair3_models_pytorch/r1041_e82_400bps_sup_v500/pileup.pt \
  -P /path/to/models/r1041_e82_400bps_sup_v500/
wget -q https://www.bio8.cs.hku.hk/clair3/clair3_models_pytorch/r1041_e82_400bps_sup_v500/full_alignment.pt \
  -P /path/to/models/r1041_e82_400bps_sup_v500/

# Run Clair3 on ONT data (CPU mode)
docker run --rm \
  -v /path/to/data:/data \
  -v /path/to/models:/models \
  getwilds/clair3:latest \
  run_clair3.sh \
  --bam_fn=/data/sample.bam \
  --ref_fn=/data/reference.fa \
  --threads=4 \
  --platform=ont \
  --model_path=/models/r1041_e82_400bps_sup_v500 \
  --output=/data/clair3_output

# Run Clair3 on ONT data with GPU acceleration (requires NVIDIA Container Toolkit)
docker run --rm --gpus all \
  -v /path/to/data:/data \
  -v /path/to/models:/models \
  getwilds/clair3:latest \
  run_clair3.sh \
  --bam_fn=/data/sample.bam \
  --ref_fn=/data/reference.fa \
  --threads=4 \
  --platform=ont \
  --model_path=/models/r1041_e82_400bps_sup_v500 \
  --output=/data/clair3_output \
  --use_gpu

# Run Clair3 on PacBio HiFi data (CPU mode)
docker run --rm \
  -v /path/to/data:/data \
  -v /path/to/models:/models \
  getwilds/clair3:latest \
  run_clair3.sh \
  --bam_fn=/data/sample.hifi.bam \
  --ref_fn=/data/reference.fa \
  --threads=8 \
  --platform=hifi \
  --model_path=/models/hifi_revio \
  --output=/data/clair3_hifi_output

# Run using Apptainer with GPU
apptainer run --nv \
  --bind /path/to/data:/data,/path/to/models:/models \
  docker://getwilds/clair3:latest \
  run_clair3.sh \
  --bam_fn=/data/sample.bam \
  --ref_fn=/data/reference.fa \
  --threads=4 \
  --platform=ont \
  --model_path=/models/r1041_e82_400bps_sup_v500 \
  --output=/data/clair3_output \
  --use_gpu
```

## Important Notes

### Pre-trained Models

Clair3 requires sequencing-platform-specific pre-trained models to call variants. These models are not included in the Docker image (each model pair is ~19 MB; the full set of 14+ models is ~265 MB). Download only the model(s) matching your sequencing data from the [Clair3 model repository](https://github.com/HKU-BAL/Clair3#pre-trained-models) and mount them at runtime as shown in the examples above.

### GPU Execution

GPU mode is opt-in via `--use_gpu` and requires the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html) on the host. Pass `--gpus all` to Docker or `--nv` to Apptainer. Without these flags the image runs in CPU mode regardless of available hardware. The image uses CUDA 12.6, which is compatible with NVIDIA driver ≥525.60.13.

### Platform Support

These images are built for `linux/amd64` only.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `nvidia/cuda:12.6.3-runtime-ubuntu24.04` as the base image
2. Adds metadata labels for documentation and attribution
3. Installs Miniforge and creates a conda environment with build tools and bioinformatics dependencies (samtools, whatshap, parallel, etc.)
4. Installs PyTorch with CUDA 12.6 support and Python dependencies (numpy, h5py, torchmetrics, etc.) via uv
5. Downloads Clair3 v2.0.0 source and builds native C extensions (`libclair3.so`) and C++ realignment modules
6. Installs PyPy 3.11 v7.3.20 for preprocessing acceleration
7. Runs `run_clair3.sh --version` and a PyTorch import check as smoke tests

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/clair3), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
