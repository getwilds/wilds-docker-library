# python-dl

This directory contains Docker images for deep learning with Python, providing a CUDA-enabled environment with popular deep learning frameworks and scientific computing libraries.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/python-dl/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/python-dl/CVEs_latest.md) )
- `1.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/python-dl/Dockerfile_1.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/python-dl/CVEs_1.0.md) )

## Image Details

These Docker images are built from NVIDIA's CUDA 11.7.1 with cuDNN 8 base image and include:

- Python 3.10: Core programming language
- TensorFlow 2.17.0: Deep learning framework
- PyTorch 2.5.0: Deep learning framework
- Keras 3.6.0: High-level neural networks API
- NumPy, Pandas, Matplotlib, Seaborn: Data manipulation and visualization
- scikit-learn, scipy: Machine learning and scientific computing
- Optuna: Hyperparameter optimization framework
- Joblib: Lightweight pipelining in Python

The images are designed to provide a comprehensive environment for deep learning and data science tasks with GPU acceleration.

## Usage

### Docker

```bash
docker pull getwilds/python-dl:latest
# or
docker pull getwilds/python-dl:1.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/python-dl:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/python-dl:latest
# or
apptainer pull docker://getwilds/python-dl:1.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/python-dl:latest
```

### Example Command

```bash
# Docker (using a hypothetical script called "train_model.py")
docker run --gpus all --rm -v /path/to/project:/project getwilds/python-dl:latest python /project/train_model.py

# Apptainer
apptainer run --nv --bind /path/to/project:/project docker://getwilds/python-dl:latest python /project/train_model.py

# Apptainer (local SIF file)
apptainer run --nv --bind /path/to/project:/project python-dl_latest.sif python /project/train_model.py
```

## GPU Support

To use GPU acceleration with this image, ensure that:

1. Your host has NVIDIA drivers installed
2. You have [NVIDIA Container Toolkit](https://github.com/NVIDIA/nvidia-docker) installed
3. You use the `--gpus all` flag when running the container

## Security Features

The python-dl Docker images include:

- Pinned versions for all dependencies to ensure reproducibility
- CUDA and cuDNN integration for GPU acceleration
- Minimal installation with only required packages

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of deep learning frameworks and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/python-dl), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses NVIDIA CUDA 11.7.1 with cuDNN 8 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs Python 3.10 and pip
4. Installs Python packages for scientific computing and visualization
5. Installs TensorFlow, Keras, and PyTorch with specific versions

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
