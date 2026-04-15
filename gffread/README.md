# gffread

This directory contains Docker images for gffread, a GFF/GTF utility for parsing, filtering, and converting genome annotation files (GFF3/GTF formats) and for extracting FASTA sequences from genomic annotations.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/gffread/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/gffread/CVEs_latest.md) )
- `0.12.7` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/gffread/Dockerfile_0.12.7) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/gffread/CVEs_0.12.7.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- gffread v0.12.7: GFF/GTF utility for annotation file manipulation and sequence extraction

The images are designed to be minimal and focused on gffread with no additional dependencies beyond what the tool requires at runtime.

## Citation

If you use gffread in your research, please cite the original authors:

```
Pertea G, Pertea M. GFF Utilities: GffRead and GffCompare.
F1000Research 2020, 9:304.
https://doi.org/10.12688/f1000research.23297.2
```

**Tool homepage:** https://github.com/gpertea/gffread

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/gffread:latest

# Or pull a specific version
docker pull getwilds/gffread:0.12.7

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/gffread:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/gffread:latest

# Or pull a specific version
apptainer pull docker://getwilds/gffread:0.12.7

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/gffread:latest
```

### Example Commands

```bash
# Convert GFF3 to GTF format
docker run --rm -v /path/to/data:/data getwilds/gffread:latest \
  gffread /data/annotations.gff3 -T -o /data/annotations.gtf

# Extract transcript sequences using a genome FASTA
docker run --rm -v /path/to/data:/data getwilds/gffread:latest \
  gffread /data/annotations.gff3 -g /data/genome.fa -w /data/transcripts.fa

# Extract protein sequences from coding transcripts
docker run --rm -v /path/to/data:/data getwilds/gffread:latest \
  gffread /data/annotations.gff3 -g /data/genome.fa -y /data/proteins.fa

# Filter annotations by a specific genomic region
docker run --rm -v /path/to/data:/data getwilds/gffread:latest \
  gffread /data/annotations.gff3 -r chr1:1000000-2000000 -o /data/filtered.gff3

# Using Apptainer with a local SIF file
apptainer run --bind /path/to/data:/data gffread_latest.sif \
  gffread /data/annotations.gff3 -T -o /data/annotations.gtf
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs build dependencies (build-essential, wget) with pinned versions
4. Downloads and compiles gffread v0.12.7 from source
5. Copies the binary to `/usr/local/bin/` and removes build dependencies
6. Performs cleanup to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/gffread), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

---
