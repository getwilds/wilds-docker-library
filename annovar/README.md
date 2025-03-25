# ANNOVAR

This directory contains Docker images for ANNOVAR, a software tool for functionally annotating genetic variants detected from high-throughput sequencing data.

## Available Versions

- `latest`: The most up-to-date stable version with hg19 reference
- `hg19`: ANNOVAR with hg19 (GRCh37) reference genome databases
- `hg38`: ANNOVAR with hg38 (GRCh38) reference genome databases

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- ANNOVAR: A software tool for functionally annotating genetic variants
- Pre-installed annotation databases:
  - refGene
  - knownGene
  - cosmic70
  - esp6500siv2_all
  - clinvar_20180603
  - gnomad211_exome

The images are designed with reference-specific variants to support different human genome reference versions.

## Usage

### Docker

```bash
docker pull getwilds/annovar:latest
# or
docker pull getwilds/annovar:hg19
# or
docker pull getwilds/annovar:hg38

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/annovar:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/annovar:latest
# or
apptainer pull docker://getwilds/annovar:hg19
# or
apptainer pull docker://getwilds/annovar:hg38

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/annovar:latest
```

### Example Command

```bash
docker run --rm -v /path/to/data:/data getwilds/annovar:hg19 table_annovar.pl input.vcf /annovar/humandb/ -buildver hg19 -out annotated -remove -protocol refGene,cosmic70,clinvar_20180603 -operation g,f,f -nastring . -vcfinput
```

## Security Features

The ANNOVAR Docker images include:

- Dynamic versioning for dependencies to ensure the latest security patches
- Pinned versions for reproducibility
- Minimal installation with only required dependencies

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs.txt` file in this directory, which is automatically updated through our GitHub Actions workflow. Critical or high-severity vulnerabilities will also be reported as GitHub issues in the repository.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Dynamically determines and pins the latest security-patched versions of dependencies
4. Downloads and extracts ANNOVAR
5. Downloads reference-specific annotation databases
6. Cleans up installation artifacts to minimize image size

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
