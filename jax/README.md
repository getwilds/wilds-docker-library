# JAX

This directory contains Docker images for JAX and related machine learning packages, providing a GPU-accelerated Python environment for high-performance numerical computing and deep learning research.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/jax/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/jax/CVEs_latest.md) )
- `0.1.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/jax/Dockerfile_0.1.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/jax/CVEs_0.1.0.md) )

## Image Details

These Docker images are built from `nvidia/cuda:12.6.3-cudnn-devel-ubuntu24.04` and include:

- JAX v0.9.0.1 / jaxlib v0.9.0.1: High-performance numerical computing with automatic differentiation and GPU/TPU acceleration
- Flax v0.12.4: Neural network library for JAX
- Optax v0.2.6: Gradient processing and optimization for JAX
- TensorFlow v2.20.0: Deep learning framework
- TensorFlow Datasets v4.9.9: Collection of ready-to-use datasets
- pandas v3.0.1, scipy v1.17.1, scikit-learn v1.8.0, matplotlib v3.10.8: Data science essentials
- opencv-python v4.13.0.92: Computer vision library
- einops v0.8.2: Flexible tensor operations
- JupyterLab v4.5.5: Interactive development environment
- ml_collections v1.1.0: ML configuration management

The images are designed to provide a comprehensive JAX-based machine learning environment with CUDA 12 GPU support.

## Citation

If you use JAX in your research, please cite the original authors:

```
Bradbury, J., Frostig, R., Hawkins, P., Johnson, M. J., Leary, C., Maclaurin, D., ... & Zhang, Q. (2018).
JAX: composable transformations of Python+NumPy programs.
http://github.com/jax-ml/jax
```

**Tool homepage:** https://github.com/jax-ml/jax

## Usage

### Docker

```bash
docker pull getwilds/jax:latest
# or
docker pull getwilds/jax:0.1.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/jax:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/jax:latest
# or
apptainer pull docker://getwilds/jax:0.1.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/jax:latest
```

### Example Python Script

```python
# example.py
import jax
import jax.numpy as jnp
from flax import nnx
import optax

# Check available devices
print(f"JAX devices: {jax.devices()}")

# Define a simple neural network using Flax
class SimpleNN(nnx.Module):
    def __init__(self, rngs: nnx.Rngs):
        self.linear1 = nnx.Linear(784, 128, rngs=rngs)
        self.linear2 = nnx.Linear(128, 10, rngs=rngs)

    def __call__(self, x):
        x = nnx.relu(self.linear1(x))
        return self.linear2(x)

# Initialize model and optimizer
model = SimpleNN(rngs=nnx.Rngs(0))
optimizer = nnx.Optimizer(model, optax.adam(1e-3))

# Create dummy data
key = jax.random.PRNGKey(0)
x = jax.random.normal(key, (32, 784))
y = jax.random.randint(key, (32,), 0, 10)
```

Run the script with:

```bash
# Docker (with GPU support)
docker run --rm --gpus all -v /path/to/script:/script getwilds/jax:latest python3 /script/example.py

# Docker (CPU only)
docker run --rm -v /path/to/script:/script getwilds/jax:latest python3 /script/example.py

# Apptainer (with GPU support)
apptainer run --nv --bind /path/to/script:/script docker://getwilds/jax:latest python3 /script/example.py

# Apptainer (local SIF file)
apptainer run --nv --bind /path/to/script:/script jax_latest.sif python3 /script/example.py
```

## Important Notes

### GPU Support

This image requires NVIDIA GPU drivers and the NVIDIA Container Toolkit for GPU acceleration. Use `--gpus all` with Docker or `--nv` with Apptainer to enable GPU support. The image is built for **amd64 architecture only**.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `nvidia/cuda:12.6.3-cudnn-devel-ubuntu24.04` as the base image
2. Adds metadata labels for documentation and attribution
3. Installs Python 3 and pip with pinned versions
4. Installs JAX ecosystem and ML packages via pip with pinned versions
5. Uses `--no-cache-dir` to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/jax), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
