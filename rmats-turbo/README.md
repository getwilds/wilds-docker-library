# rMATS-turbo

This directory contains Docker images for rMATS-turbo, a tool for detecting differential alternative splicing events from RNA-seq data. rMATS-turbo is a C/Cython implementation that is 100x faster than the original rMATS.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/rmats-turbo/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/rmats-turbo/CVEs_latest.md) )
- `4.3.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/rmats-turbo/Dockerfile_4.3.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/rmats-turbo/CVEs_4.3.0.md) )

## Image Details

These Docker images are built from Debian Bullseye and include:

- rMATS-turbo v4.3.0: Alternative splicing analysis tool for RNA-seq data
- Python 3 with Cython extensions
- R with required packages for statistical analysis (doParallel, foreach, mixtools, etc.)
- GSL, BLAS, and LAPACK for numerical computation

The images are designed to run rMATS with pre-aligned BAM files. For alignment, use a separate STAR image (available in this repository).

## Platform Availability

**Note:** This image is only built for **linux/amd64** architecture. The upstream rMATS-turbo build system uses x86-specific compiler flags (`-msse2`) that are not compatible with ARM64.

## Citation

If you use rMATS in your research, please cite the original authors:

```
Shen, S., et al. (2014). rMATS: Robust and flexible detection of differential
alternative splicing from replicate RNA-Seq data. PNAS, 111(51), E5593-E5601.
```

**Tool homepage:** https://github.com/Xinglab/rmats-turbo

## Usage

### Docker

```bash
docker pull getwilds/rmats-turbo:latest
# or
docker pull getwilds/rmats-turbo:4.3.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/rmats-turbo:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/rmats-turbo:latest
# or
apptainer pull docker://getwilds/rmats-turbo:4.3.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/rmats-turbo:latest
```

### Example Usage

```bash
# Docker - running rMATS with BAM files
docker run --rm -v /path/to/data:/data getwilds/rmats-turbo:latest \
  python /rmats/rmats.py \
  --b1 /data/sample1.bam \
  --b2 /data/sample2.bam \
  --gtf /data/annotation.gtf \
  -t paired \
  --readLength 150 \
  --nthread 4 \
  --od /data/output \
  --tmp /data/tmp

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/rmats-turbo:latest \
  python /rmats/rmats.py \
  --b1 /data/sample1.bam \
  --b2 /data/sample2.bam \
  --gtf /data/annotation.gtf \
  -t paired \
  --readLength 150 \
  --nthread 4 \
  --od /data/output \
  --tmp /data/tmp
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Debian Bullseye as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system dependencies with pinned versions (compilers, Python, R, scientific libraries)
4. Clones and builds rMATS-turbo v4.3.0 from source
5. Copies compiled artifacts to /rmats directory
6. Cleans up build directories to minimize image size
7. Runs smoke test to verify installation

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/rmats-turbo), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
