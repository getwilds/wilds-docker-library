# Ollama

This directory contains Docker images for [Ollama](https://ollama.com/), an LLM inference server, bundled with the [Sprocket](https://github.com/stjude-rust-labs/sprocket) WDL validator and the [Python ollama SDK](https://pypi.org/project/ollama/). Designed for benchmarking LLM-generated WDL scripts.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/ollama/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/ollama/CVEs_latest.md) )
- `0.21.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/ollama/Dockerfile_0.21.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/ollama/CVEs_0.21.0.md) )

## Image Details

These Docker images are built from `ollama/ollama:0.21.0` and include:

- Ollama v0.21.0: LLM inference server for running models locally
- Sprocket v0.23.0: WDL script validator
- Python ollama SDK v0.6.1: Python client library for interacting with Ollama
- Python 3 (system version from base image)

Sprocket is installed from prebuilt binaries published on the [Sprocket GitHub releases page](https://github.com/stjude-rust-labs/sprocket/releases).

## Platform Availability

Available for: linux/amd64, linux/arm64

A GPU is not required to run this image, but is highly encouraged — CPU-only execution of LLMs is significantly slower.

## Citation

This image bundles two independent tools. If you use them in your research, please cite the original authors:

- **Ollama** (LLM inference server): https://ollama.com/
- **Sprocket** (WDL execution engine): https://github.com/stjude-rust-labs/sprocket

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/ollama:latest

# Or pull a specific version
docker pull getwilds/ollama:0.21.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/ollama:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/ollama:latest

# Or pull a specific version
apptainer pull docker://getwilds/ollama:0.21.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/ollama:latest
```

### Example Commands

```bash
# Check installed versions
docker run --rm getwilds/ollama:latest ollama --version
docker run --rm getwilds/ollama:latest sprocket --version

# Start the container with GPU access
docker run --rm --gpus all -it getwilds/ollama:latest

# Inside the container, start the Ollama server
ollama serve &

# Pull a model
ollama pull llama3

# Generate a WDL script and validate it with Sprocket
python3 -c "
import ollama
response = ollama.chat(model='llama3', messages=[
    {'role': 'user', 'content': 'Write a WDL task that runs fastqc on a FASTQ file'}
])
with open('/tmp/output.wdl', 'w') as f:
    f.write(response['message']['content'])
"
sprocket lint /tmp/output.wdl
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `ollama/ollama:0.21.0` as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system dependencies with pinned versions (Python, curl, build tools)
4. Installs the Python ollama SDK via pip
5. Downloads the prebuilt Sprocket binary for the target architecture
6. Runs smoke tests to verify all tools are installed correctly

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/ollama), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
