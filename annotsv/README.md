# AnnotSV

This directory contains Docker images for AnnotSV, a tool for annotating and ranking structural variants (SVs).

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/annotsv/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/annotsv/CVEs_latest.md) )
- `3.4.4` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/annotsv/Dockerfile_3.4.4) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/annotsv/CVEs_3.4.4.md) )

## Image Details

This Docker image is built from Ubuntu 22.04 base image and includes:

- AnnotSV v3.4.4: A tool for annotating and ranking structural variants from VCF files
- Essential system dependencies for compilation and execution

The image is designed to be minimal and focused on providing AnnotSV functionality for structural variant annotation workflows.

## Usage

### Docker

```bash
docker pull getwilds/annotsv:latest
# or
docker pull getwilds/annotsv:3.4.4

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/annotsv:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/annotsv:latest
# or
apptainer pull docker://getwilds/annotsv:3.4.4

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/annotsv:latest
```

### Example Commands

```bash
# Basic help and version information
docker run --rm getwilds/annotsv:latest AnnotSV -help

# Annotate structural variants from a VCF file
docker run --rm -v /path/to/data:/data getwilds/annotsv:latest \
  AnnotSV -SVinputFile /data/input.vcf -outputDir /data/output

# Use with custom annotations database
docker run --rm -v /path/to/data:/data -v /path/to/annotations:/annotations getwilds/annotsv:latest \
  AnnotSV -SVinputFile /data/input.vcf -outputDir /data/output -annotationsDir /annotations

# Run with Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/annotsv:latest \
  AnnotSV -SVinputFile /data/input.vcf -outputDir /data/output
```

### Common AnnotSV Options

- `-SVinputFile`: Input VCF file containing structural variants
- `-outputDir`: Directory for output files
- `-annotationsDir`: Directory containing annotation databases
- `-genomeBuild`: Genome build (GRCh37/hg19 or GRCh38/hg38)
- `-SVminSize`: Minimum SV size to consider (default: 50bp)
- `-includeCI`: Include confidence intervals in output

## Integration with WILDS

This container is designed for use in structural variant analysis workflows within the WILDS ecosystem. It complements existing variant annotation tools like Annovar for comprehensive genomic analysis, particularly useful for:

- Leukemia research workflows detecting translocations and large rearrangements
- Structural variant calling pipelines using tools like Manta
- Comprehensive genomic analysis combining SNV/indel and structural variant detection

## Security Features

The AnnotSV Docker image includes:

- Minimal Ubuntu base image with only essential dependencies
- Version-pinned package installations for reproducibility
- Cleaned package cache to minimize image size
- Secure download practices with checksum verification

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/annotsv), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 22.04 as the base image for stability and security
2. Adds metadata labels for documentation and attribution
3. Sets shell options for robust error handling
4. Installs minimal dependencies with version pinning
5. Downloads and compiles AnnotSV v3.4.4 from source
6. Cleans up build artifacts and package cache to minimize image size

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
