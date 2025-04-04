# Picard

This directory contains Docker images for Picard, a set of Java command line tools for manipulating high-throughput sequencing data.

## Available Versions

- `latest`: The most up-to-date stable version (currently Picard v3.1.1)
- `3.1.1`: Picard v3.1.1

## Image Details

These Docker images are built from Ubuntu Oracular and include:

- Picard Tools: A set of Java command line tools for manipulating high-throughput sequencing data and formats such as SAM/BAM/CRAM and VCF
- OpenJDK 17: The Java runtime environment required to run Picard
- R: Required for some Picard tools that generate plots

The images are designed to be minimal and focused on Picard with its dependencies.

## Usage

### Docker

```bash
docker pull getwilds/picard:latest
# or
docker pull getwilds/picard:3.1.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/picard:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/picard:latest
# or
apptainer pull docker://getwilds/picard:3.1.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/picard:latest
```

### Example Commands

```bash
# Mark duplicates
docker run --rm -v /path/to/data:/data getwilds/picard:latest java -jar /usr/picard/picard.jar MarkDuplicates \
  I=/data/input.bam \
  O=/data/marked_duplicates.bam \
  M=/data/marked_dup_metrics.txt

# Collect alignment summary metrics
docker run --rm -v /path/to/data:/data getwilds/picard:latest java -jar /usr/picard/picard.jar CollectAlignmentSummaryMetrics \
  R=/data/reference.fasta \
  I=/data/input.bam \
  O=/data/alignment_metrics.txt

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/picard:latest java -jar /usr/picard/picard.jar MarkDuplicates \
  I=/data/input.bam \
  O=/data/marked_duplicates.bam \
  M=/data/marked_dup_metrics.txt

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data picard_latest.sif java -jar /usr/picard/picard.jar CollectAlignmentSummaryMetrics \
  R=/data/reference.fasta \
  I=/data/input.bam \
  O=/data/alignment_metrics.txt
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu Oracular as the base image
2. Adds metadata labels for documentation and attribution
3. Installs OpenJDK 17, R, and other dependencies with pinned versions
4. Downloads the Picard JAR file from the official GitHub repository
5. Places the JAR in a location that will persist in Apptainer conversions

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in this directory, which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
