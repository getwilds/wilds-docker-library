# Bowtie 2

This directory contains Docker images for Bowtie 2, a fast and sensitive gapped read aligner for aligning sequencing reads to long reference sequences.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bowtie2/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/bowtie2/CVEs_latest.md) )
- `2.5.5` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bowtie2/Dockerfile_2.5.5) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/bowtie2/CVEs_2.5.5.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- Bowtie 2 v2.5.5: A fast and sensitive gapped read aligner
- Perl: Required runtime dependency for the bowtie2 wrapper script
- Python 3: Required runtime dependency for the bowtie2 wrapper script

The images are designed to be minimal and focused on Bowtie 2 with its essential dependencies.

## Citation

If you use Bowtie 2 in your research, please cite the original authors:

```
Langmead B, Salzberg SL. Fast gapped-read alignment with Bowtie 2.
Nature Methods. 2012;9(4):357-359.
```

**Tool homepage:** https://bowtie-bio.sourceforge.net/bowtie2/

**Publication:** https://doi.org/10.1038/nmeth.1923

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/bowtie2:latest

# Or pull a specific version
docker pull getwilds/bowtie2:2.5.5

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/bowtie2:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/bowtie2:latest

# Or pull a specific version
apptainer pull docker://getwilds/bowtie2:2.5.5

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/bowtie2:latest
```

### Example Commands

```bash
# Build a Bowtie 2 index from a reference FASTA file
docker run --rm -v /path/to/data:/data getwilds/bowtie2:latest \
  bowtie2-build /data/reference.fa /data/reference_index

# Align single-end reads to an indexed reference
docker run --rm -v /path/to/data:/data getwilds/bowtie2:latest \
  bowtie2 -x /data/reference_index -U /data/reads.fastq -S /data/aligned.sam

# Align paired-end reads
docker run --rm -v /path/to/data:/data getwilds/bowtie2:latest \
  bowtie2 -x /data/reference_index -1 /data/reads_1.fastq -2 /data/reads_2.fastq \
  -S /data/aligned.sam

# Align with local alignment mode and multiple threads
docker run --rm -v /path/to/data:/data getwilds/bowtie2:latest \
  bowtie2 --local -p 4 -x /data/reference_index -U /data/reads.fastq -S /data/aligned.sam

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bowtie2:latest \
  bowtie2 -x /data/reference_index -U /data/reads.fastq -S /data/aligned.sam

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data bowtie2_latest.sif \
  bowtie2-inspect /data/reference_index
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs build and runtime dependencies (build-essential, wget, zlib1g-dev, perl, python3) with pinned versions
4. Downloads and compiles Bowtie 2 v2.5.5 from source
5. Performs cleanup to minimize image size

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/bowtie2), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
