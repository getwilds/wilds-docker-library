# SPAdes

This directory contains Docker images for SPAdes, a de novo genome assembler using de Bruijn graphs for assembling genomes from Illumina sequencing data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/spades/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/spades/CVEs_latest.md) )
- `4.2.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/spades/Dockerfile_4.2.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/spades/CVEs_4.2.0.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- SPAdes v4.2.0: A de novo genome assembler using de Bruijn graphs
- Python 3: Required runtime for SPAdes
- pigz: Parallel gzip for faster compression/decompression

The images are designed to be minimal and focused on SPAdes with its essential dependencies.

## Citation

If you use SPAdes in your research, please cite the original authors:

```
Prjibelski, A., Antipov, D., Meleshko, D., Lapidus, A., & Korobeynikov, A. (2020).
Using SPAdes De Novo Assembler. Current Protocols in Bioinformatics, 70, e102.
https://doi.org/10.1002/cpbi.102
```

**Tool homepage:** https://github.com/ablab/spades

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/spades:latest

# Or pull a specific version
docker pull getwilds/spades:4.2.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/spades:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/spades:latest

# Or pull a specific version
apptainer pull docker://getwilds/spades:4.2.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/spades:latest
```

### Example Commands

```bash
# Run SPAdes with paired-end reads
docker run --rm -v /path/to/data:/data getwilds/spades:latest \
  spades.py -1 /data/reads_1.fastq.gz -2 /data/reads_2.fastq.gz -o /data/assembly_output

# Run SPAdes in isolate mode (recommended for high-coverage isolate data)
docker run --rm -v /path/to/data:/data getwilds/spades:latest \
  spades.py --isolate -1 /data/reads_1.fastq.gz -2 /data/reads_2.fastq.gz -o /data/assembly_output

# Run metaSPAdes for metagenomic data
docker run --rm -v /path/to/data:/data getwilds/spades:latest \
  spades.py --meta -1 /data/reads_1.fastq.gz -2 /data/reads_2.fastq.gz -o /data/meta_assembly

# Run SPAdes with specified threads and memory limit
docker run --rm -v /path/to/data:/data getwilds/spades:latest \
  spades.py -1 /data/reads_1.fastq.gz -2 /data/reads_2.fastq.gz \
  --threads 8 --memory 32 -o /data/assembly_output

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/spades:latest \
  spades.py -1 /data/reads_1.fastq.gz -2 /data/reads_2.fastq.gz -o /data/assembly_output

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data spades_latest.sif \
  spades.py --isolate -1 /data/reads_1.fastq.gz -2 /data/reads_2.fastq.gz -o /data/assembly_output
```

## Important Note on Memory and Threads

SPAdes can be memory-intensive, especially for large genomes or metagenomic datasets. By default, SPAdes will attempt to use all available memory and threads on the system. For controlled resource usage, use the `--threads` and `--memory` options:

```bash
# Limit to 8 threads and 64GB memory
docker run --rm -v /path/to/data:/data getwilds/spades:latest \
  spades.py -1 /data/reads_1.fastq.gz -2 /data/reads_2.fastq.gz \
  --threads 8 --memory 64 -o /data/assembly_output
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Dynamically determines and pins the latest security-patched versions of dependencies
4. Downloads the pre-built SPAdes binary from GitHub releases
5. Sets up environment variables for locale and PATH
6. Performs cleanup to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/spades), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
