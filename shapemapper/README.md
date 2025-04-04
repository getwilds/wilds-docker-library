# shapemapper

This directory contains Docker images for ShapeMapper, a tool for high-throughput RNA structure probing analysis.

## Available Versions

- `latest`: The most up-to-date stable version (currently ShapeMapper v2.3)
- `2.3`: ShapeMapper v2.3

## Image Details

These Docker images are built from Ubuntu 22.04 and include:

- ShapeMapper v2.3: A software tool for RNA structure probing experiments
- Python 3: Required for running ShapeMapper scripts

The images are designed to be minimal and focused on providing a functional ShapeMapper installation with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/shapemapper:latest
# or
docker pull getwilds/shapemapper:2.3

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/shapemapper:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/shapemapper:latest
# or
apptainer pull docker://getwilds/shapemapper:2.3

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/shapemapper:latest
```

### Example Command

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/shapemapper:latest shapemapper \
  --target /data/target.fa \
  --out /data/output_directory \
  --modified --folder /data/modified_reads \
  --untreated --folder /data/untreated_reads

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/shapemapper:latest shapemapper \
  --target /data/target.fa \
  --out /data/output_directory \
  --modified --folder /data/modified_reads \
  --untreated --folder /data/untreated_reads

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data shapemapper_latest.sif shapemapper \
  --target /data/target.fa \
  --out /data/output_directory \
  --modified --folder /data/modified_reads \
  --untreated --folder /data/untreated_reads
```

## Security Features

The ShapeMapper Docker images include:

- Dynamic versioning for all dependencies to ensure the latest security patches
- Pinned versions for reproducibility
- Non-interactive installation to prevent prompts
- Minimal installation with only required dependencies

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in this directory, which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 22.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Sets environment variables for non-interactive installation
4. Dynamically determines and pins the latest security-patched versions of dependencies
5. Downloads ShapeMapper from the official GitHub release
6. Extracts and installs ShapeMapper to the /opt directory
7. Sets up the working directory and PATH environment

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
