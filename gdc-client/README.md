# GDC Data Transfer Tool (gdc-client)

This directory contains Docker images for the GDC Data Transfer Tool (gdc-client), the official command-line tool for downloading and uploading data from the NCI Genomic Data Commons (GDC).

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/gdc-client/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/gdc-client/CVEs_latest.md) )
- `2.3.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/gdc-client/Dockerfile_2.3.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/gdc-client/CVEs_2.3.0.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- GDC Data Transfer Tool v2.3: Command-line tool for data transfer to/from the GDC
- Python 3: Required runtime for gdc-client
- Git: Required for installation from GitHub source

The images are designed to provide a minimal, reproducible environment for accessing TCGA and other cancer genomics datasets from the Genomic Data Commons. The gdc-client is installed directly from the official NCI-GDC GitHub repository.

## Citation

If you use the GDC Data Transfer Tool in your research, please cite the Genomic Data Commons:

```
National Cancer Institute GDC Data Portal. https://gdc.cancer.gov
```

**Tool homepage:** https://gdc.cancer.gov/access-data/gdc-data-transfer-tool

**Documentation:** https://docs.gdc.cancer.gov/Data_Transfer_Tool/Users_Guide/Getting_Started/

**GitHub repository:** https://github.com/NCI-GDC/gdc-client

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/gdc-client:latest

# Or pull a specific version
docker pull getwilds/gdc-client:2.3.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/gdc-client:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/gdc-client:latest

# Or pull a specific version
apptainer pull docker://getwilds/gdc-client:2.3.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/gdc-client:latest
```

### Example Commands

```bash
# Download a single file using its UUID
docker run --rm -v /path/to/data:/data getwilds/gdc-client:latest \
  gdc-client download 22a29915-6712-4f7a-8dba-985ae9a1f005

# Download multiple files from a manifest
docker run --rm -v /path/to/data:/data getwilds/gdc-client:latest \
  gdc-client download -m /data/gdc_manifest.txt

# Download with multiple threads for better performance
docker run --rm -v /path/to/data:/data getwilds/gdc-client:latest \
  gdc-client download -m /data/gdc_manifest.txt -n 8

# Download files using a token for controlled-access data
docker run --rm -v /path/to/data:/data -v /path/to/token:/token getwilds/gdc-client:latest \
  gdc-client download -m /data/gdc_manifest.txt -t /token/gdc-user-token.txt

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/gdc-client:latest \
  gdc-client download -m /data/gdc_manifest.txt -n 8

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data gdc-client_latest.sif \
  gdc-client download 22a29915-6712-4f7a-8dba-985ae9a1f005
```

## Important Notes

### Data Download Location

By default, gdc-client downloads files to the current working directory. The Docker image sets `/data` as the working directory, so files will be downloaded there when you mount your local directory to `/data`.

### Authentication for Controlled-Access Data

To download controlled-access data, you need a GDC authentication token:

1. Log in to the [GDC Data Portal](https://portal.gdc.cancer.gov/)
2. Download your authentication token
3. Mount the token file and use the `-t` flag:

```bash
docker run --rm -v /path/to/data:/data -v /path/to/token.txt:/token.txt \
  getwilds/gdc-client:latest \
  gdc-client download -m /data/manifest.txt -t /token.txt
```

### Generating Manifests

Manifests can be generated from the GDC Data Portal by:

1. Selecting files in the repository or cart
2. Clicking the "Download" button
3. Selecting "Manifest" option

The manifest is a tab-delimited file containing file UUIDs and metadata.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system dependencies (Python 3, pip, git) with pinned versions for security
4. Installs gdc-client v2.3 directly from the official NCI-GDC GitHub repository using pip
5. Performs cleanup to minimize image size
6. Runs a smoke test to verify the installation
7. Sets `/data` as the working directory

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/gdc-client), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
