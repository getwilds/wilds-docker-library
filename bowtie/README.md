# Bowtie

This directory contains Docker images for Bowtie, an ultrafast, memory-efficient short read aligner that aligns short DNA sequences to the human genome and other reference sequences.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bowtie/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/bowtie/CVEs_latest.md) )
- `1.3.1` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bowtie/Dockerfile_1.3.1) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/bowtie/CVEs_1.3.1.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- Bowtie v1.3.1: An ultrafast, memory-efficient short read aligner
- Samtools v1.19: A suite of utilities for manipulating alignments in the SAM/BAM format
- Perl: Required runtime dependency for Bowtie wrapper scripts
- Python 3: Required runtime dependency for Bowtie wrapper scripts

The images include Samtools alongside Bowtie for common alignment workflows (e.g., piping Bowtie output directly to `samtools view` for BAM conversion).

## Citation

If you use Bowtie in your research, please cite the original authors:

```
Langmead B, Trapnell C, Pop M, Salzberg SL. Ultrafast and memory-efficient
alignment of short DNA sequences to the human genome. Genome Biology 10:R25 (2009).
```

**Tool homepage:** https://bowtie-bio.sourceforge.net/

**Publication:** https://doi.org/10.1186/gb-2009-10-3-r25

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/bowtie:latest

# Or pull a specific version
docker pull getwilds/bowtie:1.3.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/bowtie:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/bowtie:latest

# Or pull a specific version
apptainer pull docker://getwilds/bowtie:1.3.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/bowtie:latest
```

### Example Commands

```bash
# Build a Bowtie index from a reference FASTA file
docker run --rm -v /path/to/data:/data getwilds/bowtie:latest \
  bowtie-build /data/reference.fa /data/reference_index

# Align single-end reads to an indexed reference
docker run --rm -v /path/to/data:/data getwilds/bowtie:latest \
  bowtie -x /data/reference_index -q /data/reads.fastq -S /data/aligned.sam

# Align paired-end reads
docker run --rm -v /path/to/data:/data getwilds/bowtie:latest \
  bowtie -x /data/reference_index -1 /data/reads_1.fastq -2 /data/reads_2.fastq \
  -S /data/aligned.sam

# Align and convert to sorted BAM in one step
docker run --rm -v /path/to/data:/data getwilds/bowtie:latest \
  bash -c "bowtie -x /data/reference_index -q /data/reads.fastq -S - | \
  samtools sort -o /data/aligned.sorted.bam && samtools index /data/aligned.sorted.bam"

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bowtie:latest \
  bowtie -x /data/reference_index -q /data/reads.fastq -S /data/aligned.sam

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data bowtie_latest.sif \
  bowtie-inspect /data/reference_index
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system and build dependencies with pinned versions
4. Downloads and installs the pre-built Bowtie binary for the target architecture
5. Downloads and compiles Samtools v1.19 from source
6. Performs cleanup to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/bowtie), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
