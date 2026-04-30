# umitools

This directory contains Docker images for UMI-tools, a collection of tools for handling Unique Molecular Identifiers (UMIs) in high-throughput sequencing data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/umitools/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/umitools/CVEs_latest.md) )
- `1.1.6` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/umitools/Dockerfile_1.1.6) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/umitools/CVEs_1.1.6.md) )

## Image Details

These Docker images are built from Python 3.11-bookworm and include:

- UMI-tools v1.1.6: Tools for dealing with Unique Molecular Identifiers in NGS data
- Samtools v1.20: Utilities for manipulating SAM/BAM/CRAM alignment files, commonly used alongside UMI-tools for sorting, indexing, and inspecting BAMs before deduplication

The images are designed to be minimal and focused on a specific version of UMI-tools with its dependencies, optimized for handling UMIs in next-generation sequencing data analysis pipelines.

## Usage

### Docker

```bash
docker pull getwilds/umitools:latest
# or
docker pull getwilds/umitools:1.1.6

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/umitools:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/umitools:latest
# or
apptainer pull docker://getwilds/umitools:1.1.6

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/umitools:latest
```

### Example Commands

```bash
# Extract UMIs from FASTQ files
docker run --rm -v /path/to/data:/data getwilds/umitools:latest umi_tools extract \
  --bc-pattern=NNNNNN \
  --stdin=/data/reads.fastq.gz \
  --stdout=/data/reads.extracted.fastq.gz

# Sort and index a BAM file with samtools before deduplication
docker run --rm -v /path/to/data:/data getwilds/umitools:latest \
  bash -c "samtools sort -o /data/mapped.sorted.bam /data/mapped.bam && samtools index /data/mapped.sorted.bam"

# Deduplicate BAM files based on UMIs
docker run --rm -v /path/to/data:/data getwilds/umitools:latest umi_tools dedup \
  --stdin=/data/mapped.sorted.bam \
  --stdout=/data/deduplicated.bam

# Group reads by UMI
docker run --rm -v /path/to/data:/data getwilds/umitools:latest umi_tools group \
  --stdin=/data/mapped.sorted.bam \
  --stdout=/data/grouped.tsv \
  --output-bam \
  --paired

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/umitools:latest umi_tools extract \
  --bc-pattern=NNNNNN \
  --stdin=/data/reads.fastq.gz \
  --stdout=/data/reads.extracted.fastq.gz

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data umitools_latest.sif umi_tools dedup \
  --stdin=/data/mapped.bam \
  --stdout=/data/deduplicated.bam
```

## Security Features

The UMI-tools Docker images include:

- Python 3.11 from Debian Bookworm for a secure base
- Installation via pip with no-cache-dir to minimize image size
- Pinned versions for reproducibility

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in this directory, which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Python 3.11-bookworm as the base image
2. Adds metadata labels for documentation and attribution
3. Installs build prerequisites and compiles Samtools v1.20 from source
4. Installs UMI-tools with a specific version via pip (no-cache-dir to keep the image size minimal)
5. Runs a smoke test verifying both `umi_tools` and `samtools` are functional

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
