# Salmon

This directory contains Docker images for Salmon, a "wicked-fast program to produce highly-accurate, transcript-level quantification estimates from RNA-seq data" using selective alignment.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/salmon/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/salmon/CVEs_latest.md) )
- `1.10.3` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/salmon/Dockerfile_1.10.3) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/salmon/CVEs_1.10.3.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- Salmon v1.10.3: Fast and bias-aware transcript quantification tool for RNA-seq data
- System dependencies: Boost, TBB (Threading Building Blocks), zlib, bz2, lzma, zstd, curl

The images are designed to be minimal and focused on Salmon with its essential dependencies. Salmon is built from source to ensure compatibility across both AMD64 and ARM64 architectures.

## Citation

If you use Salmon in your research, please cite the original authors:

```
Patro, R., Duggal, G., Love, M. I., Irizarry, R. A., & Kingsford, C. (2017).
Salmon provides fast and bias-aware quantification of transcript expression.
Nature Methods, 14(4), 417-419.
https://doi.org/10.1038/nmeth.4197
```

**Tool homepage:** https://github.com/COMBINE-lab/salmon

**Documentation:** https://salmon.readthedocs.io/

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/salmon:latest

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/salmon:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/salmon:latest

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/salmon:latest
```

### Example Commands

```bash
# Example 1: Index a transcriptome (FASTA file)
docker run --rm -v /path/to/data:/data getwilds/salmon:latest \
  salmon index -t /data/transcripts.fa -i /data/salmon_index

# Example 2: Quantify paired-end reads
docker run --rm -v /path/to/data:/data getwilds/salmon:latest \
  salmon quant -i /data/salmon_index \
  -l A \
  -1 /data/reads_1.fastq.gz \
  -2 /data/reads_2.fastq.gz \
  -o /data/salmon_output

# Example 3: Quantify single-end reads with validation
docker run --rm -v /path/to/data:/data getwilds/salmon:latest \
  salmon quant -i /data/salmon_index \
  -l A \
  -r /data/reads.fastq.gz \
  --validateMappings \
  -o /data/salmon_output

# Example 4: Using Apptainer with paired-end reads
apptainer run --bind /path/to/data:/data docker://getwilds/salmon:latest \
  salmon quant -i /data/salmon_index \
  -l A \
  -1 /data/reads_1.fastq.gz \
  -2 /data/reads_2.fastq.gz \
  -o /data/salmon_output

# Example 5: Using a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data salmon_latest.sif \
  salmon quant -i /data/salmon_index \
  -l A \
  -1 /data/reads_1.fastq.gz \
  -2 /data/reads_2.fastq.gz \
  -o /data/salmon_output
```

## Important Notes

### Library Type Detection

Salmon can automatically detect the library type using `-l A` (automatic detection), which is convenient for most use cases. However, you can also specify the library type explicitly (e.g., `-l ISF` for paired-end reads with inward-facing reads from the forward strand). See the [Salmon documentation](https://salmon.readthedocs.io/en/latest/library_type.html) for more details on library types.

### Selective Alignment

Starting with version 1.0.0, Salmon uses selective alignment by default, which provides improved accuracy. This is the mapping strategy used in these images.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system dependencies with pinned versions (build tools, Boost, TBB, compression libraries)
4. Downloads Salmon v1.10.3 source code from GitHub
5. Builds Salmon from source using CMake
6. Performs cleanup to minimize image size
7. Runs a smoke test to verify the installation

Building from source ensures compatibility across both AMD64 and ARM64 architectures.

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/salmon), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
