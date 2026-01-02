# MEGAHIT

This directory contains Docker images for MEGAHIT, an ultra-fast and memory-efficient NGS assembler optimized for metagenomes. It also works well on generic single genome assembly (small or mammalian size) and single-cell assembly.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/megahit/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/megahit/CVEs_latest.md) )
- `1.2.9` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/megahit/Dockerfile_1.2.9) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/megahit/CVEs_1.2.9.md) )

## Image Details

These Docker images are built from Ubuntu 22.04 and include:

- MEGAHIT v1.2.9: Ultra-fast and memory-efficient metagenome assembler
- Python3: Required for MEGAHIT's wrapper scripts (with `python` symlink for compatibility)
- libgomp1: OpenMP runtime library for parallel processing
- gzip and bzip2: Compression utilities for handling sequence data

The images are designed to be minimal and focused on MEGAHIT with its essential runtime dependencies. Build-time dependencies (cmake, g++, make) are removed after compilation to reduce the final image size.

## Architecture Support

These images are built for **AMD64 (x86_64) only**. MEGAHIT v1.2.9 contains x86-specific CPU optimizations and intrinsics that prevent compilation on ARM64 architecture. For users on ARM64 systems (e.g., Apple Silicon Macs), the AMD64 image can still be used via emulation (Docker Desktop handles this automatically), which is sufficient for local testing and development.

## Citation

If you use MEGAHIT in your research, please cite the original authors:

```
Li, D., Liu, C-M., Luo, R., Sadakane, K., and Lam, T-W. (2015)
MEGAHIT: An ultra-fast single-node solution for large and complex metagenomics
assembly via succinct de Bruijn graph.
Bioinformatics, doi: 10.1093/bioinformatics/btv033
PMID: 25609793
```

**Tool homepage:** https://github.com/voutcn/megahit

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/megahit:latest

# Or pull a specific version
docker pull getwilds/megahit:1.2.9

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/megahit:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/megahit:latest

# Or pull a specific version
apptainer pull docker://getwilds/megahit:1.2.9

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/megahit:latest
```

### Example Commands

```bash
# Example 1: Basic metagenome assembly from paired-end reads
docker run --rm -v /path/to/data:/data getwilds/megahit:latest \
  megahit -1 /data/reads_R1.fastq.gz -2 /data/reads_R2.fastq.gz \
  -o /data/megahit_output

# Example 2: Assembly with multiple input files
docker run --rm -v /path/to/data:/data getwilds/megahit:latest \
  megahit -1 /data/sample1_R1.fq.gz,/data/sample2_R1.fq.gz \
  -2 /data/sample1_R2.fq.gz,/data/sample2_R2.fq.gz \
  -o /data/megahit_assembly

# Example 3: Assembly with single-end reads
docker run --rm -v /path/to/data:/data getwilds/megahit:latest \
  megahit -r /data/reads.fastq.gz -o /data/megahit_se_output

# Example 4: Using custom k-mer sizes and minimum contig length
docker run --rm -v /path/to/data:/data getwilds/megahit:latest \
  megahit -1 /data/reads_R1.fastq.gz -2 /data/reads_R2.fastq.gz \
  --k-list 21,29,39,59,79,99 --min-contig-len 500 \
  -o /data/megahit_custom

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/megahit:latest \
  megahit -1 /data/reads_R1.fastq.gz -2 /data/reads_R2.fastq.gz \
  -o /data/megahit_output

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data megahit_latest.sif \
  megahit -1 /data/reads_R1.fastq.gz -2 /data/reads_R2.fastq.gz \
  -o /data/megahit_output
```

## Important Notes

### Memory Requirements

MEGAHIT is designed to be memory-efficient, but large datasets may still require significant RAM. By default, MEGAHIT uses 90% of available memory. You can control memory usage with the `-m` or `--memory` flag:

```bash
# Limit MEGAHIT to 16GB of RAM
docker run --rm -v /path/to/data:/data getwilds/megahit:latest \
  megahit -1 /data/reads_R1.fastq.gz -2 /data/reads_R2.fastq.gz \
  --memory 0.16 -o /data/megahit_output
```

### Temporary Files

MEGAHIT creates temporary files during assembly. Make sure your output directory has sufficient disk space. To use a custom temporary directory, mount it and specify with `--tmp-dir`:

```bash
docker run --rm -v /path/to/data:/data -v /path/to/tmp:/tmp getwilds/megahit:latest \
  megahit -1 /data/reads_R1.fastq.gz -2 /data/reads_R2.fastq.gz \
  --tmp-dir /tmp -o /data/megahit_output
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 22.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system dependencies with pinned versions for reproducibility
4. Downloads and compiles MEGAHIT v1.2.9 from source
5. Removes build-time dependencies (cmake, g++, make) to reduce image size
6. Creates a `python` symlink to `python3` for MEGAHIT wrapper compatibility
7. Sets working directory to /data
8. Performs a smoke test to verify installation

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/megahit), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
