# Cell Ranger

This directory contains a Dockerfile for Cell Ranger, 10x Genomics' analysis pipeline for single-cell RNA-seq data.

## Licensing Notice

**Cell Ranger is proprietary software distributed by 10x Genomics.** Users must accept the [10x Genomics End User License Agreement](https://www.10xgenomics.com/support/software/cell-ranger/downloads) before downloading Cell Ranger. Because of this licensing restriction, **pre-built images are not publicly available** on DockerHub. Instead, we provide a Dockerfile that you can build yourself after obtaining your own download URL from 10x Genomics.

## Dockerfile

- [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/cellranger/Dockerfile_latest)

## Image Details

The Docker image is built from Ubuntu Noble and includes:

- Cell Ranger: A set of analysis pipelines that process Chromium single-cell RNA-seq output to align reads, generate feature-barcode matrices, perform clustering and other secondary analysis

The image is designed to be minimal and focused on Cell Ranger with its dependencies.

## Platform Availability

**AMD64 only**: Cell Ranger only supports x86_64 (AMD64) Linux systems. These images will not run natively on ARM-based systems (e.g., Apple Silicon Macs). Docker Desktop on Apple Silicon can run these images through emulation, though with reduced performance.

## Building the Image

Since Cell Ranger requires accepting the 10x Genomics license agreement, you must obtain your own download URL before building.

### Step 1: Get a Download URL

1. Visit the [Cell Ranger Downloads page](https://www.10xgenomics.com/support/software/cell-ranger/downloads)
2. Accept the license agreement
3. Copy the download URL for your desired version (e.g., `cellranger-10.0.0.tar.gz`)

> **Note:** Download URLs contain a signed key that expires. You will need to obtain a fresh URL each time you build.

### Step 2: Build the Image

The Dockerfile accepts two build arguments:

| Argument | Required | Default | Description |
|---|---|---|---|
| `CELLRANGER_URL` | Yes | — | The signed download URL from 10x Genomics |
| `CELLRANGER_VERSION` | No | `10.0.0` | The Cell Ranger version being installed |

```bash
# Build the default version (10.0.0)
docker build --platform linux/amd64 \
  --build-arg CELLRANGER_URL="<your-download-url>" \
  -t cellranger:10.0.0 \
  -f cellranger/Dockerfile_latest .

# Build an older version
docker build --platform linux/amd64 \
  --build-arg CELLRANGER_URL="<your-download-url>" \
  --build-arg CELLRANGER_VERSION=6.0.2 \
  -t cellranger:6.0.2 \
  -f cellranger/Dockerfile_latest .
```

The build will fail with an informative error if `CELLRANGER_URL` is not provided.

## Usage

### Docker

```bash
docker run --rm -v /path/to/data:/data cellranger:10.0.0 cellranger count \
  --id=sample_run \
  --fastqs=/data/fastqs \
  --transcriptome=/data/reference \
  --sample=sample1
```

### Singularity/Apptainer

After building the Docker image locally, you can convert it to a SIF file:

```bash
# Save Docker image to a tar archive and convert
docker save cellranger:10.0.0 -o cellranger_10.0.0.tar
apptainer build cellranger_10.0.0.sif docker-archive://cellranger_10.0.0.tar

# Run with Apptainer
apptainer run --bind /path/to/data:/data cellranger_10.0.0.sif cellranger count \
  --id=sample_run \
  --fastqs=/data/fastqs \
  --transcriptome=/data/reference \
  --sample=sample1
```

## Hosting a Private Image

If you or your organization would like to avoid rebuilding the image every time, you can push it to a **private** container registry for reuse. This keeps you in compliance with 10x Genomics' licensing while providing convenient access for your team.

### Push to GitHub Container Registry (GHCR)

```bash
# Build the image (see "Building the Image" above)
docker build --platform linux/amd64 \
  --build-arg CELLRANGER_URL="<your-download-url>" \
  -t ghcr.io/<your-org>/cellranger:10.0.0 \
  -f cellranger/Dockerfile_latest .

# Authenticate with GHCR using the GitHub CLI (recommended)
gh auth refresh --scopes write:packages
gh auth token | docker login ghcr.io -u USERNAME --password-stdin

# Push the image
docker push ghcr.io/<your-org>/cellranger:10.0.0

# Pull from another machine
docker pull ghcr.io/<your-org>/cellranger:10.0.0

# Or with Apptainer (requires Apptainer v1.1.0+)
gh auth refresh --scopes read:packages
export APPTAINER_DOCKER_USERNAME=<your-github-username>
export APPTAINER_DOCKER_PASSWORD=$(gh auth token)
apptainer pull docker://ghcr.io/<your-org>/cellranger:10.0.0
```

### Push to DockerHub (Private Repository)

```bash
# Build the image
docker build --platform linux/amd64 \
  --build-arg CELLRANGER_URL="<your-download-url>" \
  -t <your-username>/cellranger:10.0.0 \
  -f cellranger/Dockerfile_latest .

# Log in to DockerHub
docker login -u <your-username>

# Push the image (make sure the repo is set to private on DockerHub)
docker push <your-username>/cellranger:10.0.0
```

> **Important:** Ensure your registry repository is set to **private** to comply with 10x Genomics' licensing terms. Do not distribute Cell Ranger images publicly.

### Using with WDL Workflows (Sprocket/Cromwell)

If you're running WDL workflows that reference a private GHCR image, environment variables like `APPTAINER_DOCKER_PASSWORD` won't persist into the workflow engine's execution environment. Instead, store your GHCR credentials on the machine so Apptainer can authenticate automatically:

```bash
# Store GHCR credentials persistently (one-time setup per machine)
gh auth refresh --scopes read:packages
apptainer remote login --username <your-github-username> docker://ghcr.io
# When prompted for a password, paste the output of: gh auth token
```

Alternatively, you can pre-pull the image before running the workflow so Apptainer uses the cached SIF file instead of pulling at runtime:

```bash
apptainer pull cellranger_10.0.0.sif docker://ghcr.io/<your-org>/cellranger:10.0.0
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu Noble as the base image
2. Declares build arguments for the Cell Ranger version and download URL
3. Adds metadata labels for documentation and attribution
4. Sets shell options for better error handling in pipelines
5. Validates that the required download URL was provided
6. Installs prerequisites with pinned versions
7. Downloads and extracts Cell Ranger pre-built binary using the provided URL
8. Adds Cell Ranger to the PATH and sets working directory
9. Runs a smoke test to verify the installation

## Source Repository

This Dockerfile is maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
