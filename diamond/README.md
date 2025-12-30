# DIAMOND

This directory contains Docker images for DIAMOND, a  BLAST-compatible sequence aligner

[Official Documentation](https://github.com/bbuchfink/diamond)

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/diamond/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/diamond/CVEs_latest.md) )

- `2.1.16` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/diamond/Dockerfile_2.1.16) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/diamond/CVEs_2.1.16.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- DIAMOND v2.1.16: Accelerated sequence aligner for protein and translated DNA searches
- NCBI BLAST+: Additional BLAST tools for sequence analysis

DIAMOND is designed to be significantly faster than BLAST while maintaining high sensitivity. The images are optimized for alignment of sequencing reads and protein queries against large reference databases.

## Citation

If you use DIAMOND in your research, please cite the original authors:

```
Buchfink B, Reuter K, Drost HG, "Sensitive protein alignments at tree-of-life scale using DIAMOND", Nature Methods 18, 366–368 (2021). doi:10.1038/s41592-021-01101-x
```

**Tool homepage:** https://github.com/bbuchfink/diamond

**Documentation:** https://github.com/bbuchfink/diamond/wiki

## Usage

### Docker

```bash
docker pull getwilds/diamond:latest

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/diamond:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/diamond:latest

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/diamond:latest
```

### Example Commands

```bash
# Create a DIAMOND Database
docker run --rm -v /path/to/data:/data getwilds/diamond:latest \
  diamond makedb --in /data/reference.fasta --db /data/ref_database

# Protein alignment
docker run --rm -v /path/to/data:/data getwilds/diamond:latest \
  diamond blastp --db /data/ref_database --query /data/queries.fasta --out /data/matches.tsv
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs wget and NCBI BLAST+ with pinned versions
4. Downloads and extracts DIAMOND pre-built binary
5. Installs binary to `/usr/local/bin/`
6. Includes smoke tests to verify installation (`diamond test` and sample alignment)

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/diamond), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
