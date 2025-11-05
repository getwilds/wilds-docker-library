# RSeQC

This directory contains Docker images for RSeQC, a comprehensive Python-based quality control toolkit for RNA-seq data.

[Official Documentation](https://rseqc.sourceforge.net/)

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/rseqc/Dockerfile_latest) | Vulnerability Report )
- `5.0.4` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/rseqc/Dockerfile_5.0.4) | Vulnerability Report )

## Image Details

These Docker images are built from the Python 3.12 slim image and include:

- **RSeQC v5.0.4**: Comprehensive RNA-seq quality control package with 40+ analysis modules
- **pysam v0.22.1**: Python interface for SAM/BAM files
- **bx-python v0.13.0**: Python library for genomic interval operations
- **pyBigWig v0.3.23**: Python library for bigWig file access

The images are designed to be minimal and focused on RSeQC with its essential dependencies.

## About RSeQC

RSeQC provides modules to evaluate RNA-seq data quality including:
- Sequence quality and nucleotide composition bias
- PCR bias and GC bias analysis
- Read distribution and coverage uniformity
- Transcript integrity assessment
- Junction annotation and analysis
- Duplication detection
- Single-cell RNA-seq QC functions

**Important Requirements:**
- BAM files must be sorted and indexed using samtools
- Gene models should be in BED format (12-column standard)
- Default minimum mapping quality is 30 (phred-scaled)

## Usage

### Docker

```bash
docker pull getwilds/rseqc:latest
# or
docker pull getwilds/rseqc:5.0.4

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/rseqc:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/rseqc:latest
# or
apptainer pull docker://getwilds/rseqc:5.0.4

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/rseqc:latest
```

### Example Commands

RSeQC provides numerous analysis tools. Here are some common examples:

#### Read Distribution Analysis

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/rseqc:latest \
  read_distribution.py -i /data/sample.bam -r /data/genes.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/rseqc:latest \
  read_distribution.py -i /data/sample.bam -r /data/genes.bed
```

#### Gene Body Coverage

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/rseqc:latest \
  geneBody_coverage.py -r /data/genes.bed -i /data/sample.bam -o /data/output

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/rseqc:latest \
  geneBody_coverage.py -r /data/genes.bed -i /data/sample.bam -o /data/output
```

#### Junction Annotation

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/rseqc:latest \
  junction_annotation.py -i /data/sample.bam -o /data/junction -r /data/genes.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/rseqc:latest \
  junction_annotation.py -i /data/sample.bam -o /data/junction -r /data/genes.bed
```

#### BAM Statistics

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/rseqc:latest \
  bam_stat.py -i /data/sample.bam

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/rseqc:latest \
  bam_stat.py -i /data/sample.bam
```

#### Infer Experiment (strandedness)

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/rseqc:latest \
  infer_experiment.py -r /data/genes.bed -i /data/sample.bam

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/rseqc:latest \
  infer_experiment.py -r /data/genes.bed -i /data/sample.bam
```

### Available RSeQC Tools

The image includes all 40+ RSeQC analysis modules. Some of the most commonly used tools include:

| Tool | Description |
|------|-------------|
| `bam_stat.py` | Summarize mapping statistics of BAM file |
| `read_distribution.py` | Calculate read distribution over genomic features |
| `geneBody_coverage.py` | Read coverage over gene body |
| `junction_annotation.py` | Compare splice junctions to reference |
| `junction_saturation.py` | Check if sequencing depth is sufficient |
| `infer_experiment.py` | Infer RNA-seq protocol (strandedness) |
| `inner_distance.py` | Calculate inner distance between paired reads |
| `read_duplication.py` | Determine duplication rate |
| `read_GC.py` | Determine GC% and read count |
| `RNA_fragment_size.py` | Calculate fragment size for paired-end RNA-seq |
| `RPKM_saturation.py` | Check if sequencing depth is sufficient for genes |
| `clipping_profile.py` | Estimate clipping profile of RNA-seq reads |
| `insertion_profile.py` | Calculate distribution of inserted nucleotides |
| `deletion_profile.py` | Calculate distribution of deleted nucleotides |
| `mismatch_profile.py` | Calculate mismatch profile |

For a complete list and detailed usage, see the [official RSeQC documentation](https://rseqc.sourceforge.net/).

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Python 3.12 slim as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system dependencies required for compiling Python packages (zlib, bzip2, lzma, curl)
4. Installs RSeQC and its dependencies via pip with pinned versions
5. Uses `--no-cache-dir` to minimize image size
6. Includes a smoke test to verify installation

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/rseqc), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

## Contributing

See the [CONTRIBUTING.md](../.github/CONTRIBUTING.md) for guidelines on how to contribute to this project.

## License

RSeQC is distributed under the GNU General Public License v3. This Docker image is distributed under the MIT License. See the [LICENSE](../LICENSE) file for details.
