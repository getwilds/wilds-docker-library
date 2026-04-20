# Ollama

Docker image bundling [Ollama](https://ollama.com/) with the [Sprocket](https://github.com/stjude-rust-labs/sprocket) WDL validator, designed for benchmarking LLM-generated WDL scripts.

## Available Versions

| Tag | Ollama Version | Sprocket Version | Python ollama SDK |
|-----|---------------|-----------------|-------------------|
| latest | 0.21.0 | 0.23.0 | 0.6.1 |
| 0.21.0 | 0.21.0 | 0.23.0 | 0.6.1 |
| 0.5.4 | 0.5.4 | 0.23.0 | 0.4.4 |

## Platform Availability

Available for: linux/amd64, linux/arm64

## Usage

### Docker

```bash
docker pull getwilds/ollama:latest
docker run --rm getwilds/ollama:latest ollama --version
```

### Apptainer/Singularity

```bash
apptainer pull docker://getwilds/ollama:latest
apptainer run ollama_latest.sif ollama --version
```

### Example: Run a Model and Validate WDL Output

```bash
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

## Installed Components

- Ollama: v0.21.0 (LLM inference server)
- Sprocket: v0.23.0 (WDL script validator, compiled from source via cargo)
- Python ollama SDK: v0.6.1
- Python 3 (system version from base image)

Note: Sprocket is compiled from source during the Docker build using Rust's `cargo install`. The Rust toolchain is removed after compilation to minimize image size.

## Security

Vulnerability reports are available in this directory as `CVEs_*.md` files.
Images are scanned monthly and on each build.

## Contributing

See the [CONTRIBUTING.md](../.github/CONTRIBUTING.md) for guidelines.
