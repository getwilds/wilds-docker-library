# smoove

This directory contains Docker images for smoove, a streamlined workflow for structural variant calling and genotyping using LUMPY and other established tools.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/smoove/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/smoove/CVEs_latest.md) )
- `0.2.8` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/smoove/Dockerfile_0.2.8) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/smoove/CVEs_0.2.8.md) )

## Image Details

These Docker images are built from Ubuntu 22.04 and include:

- **smoove v0.2.8**: A streamlined workflow that wraps LUMPY, samtools, and other tools
- **LUMPY-SV**: Core structural variant calling engine with lumpy and lumpy_filter
- **samtools v1.19.2**: Suite of programs for interacting with SAM/BAM files
- **bcftools v1.19**: Utilities for variant calling and manipulating VCFs/BCFs
- **htslib v1.19.1**: High-throughput sequencing data processing library
- **svtyper**: Genotyping tool for structural variants
- **mosdepth v0.3.6**: Fast BAM/CRAM depth calculation
- **duphold v0.2.3**: Annotates SVs with read-depth changes
- **gsort v0.1.4**: Genomic interval sorting utility

**Note**: The latest images do not include svtools due to Python 2/3 compatibility issues. svtools is optional and mainly needed for large cohorts (>100 samples). It can be added separately if required.

**Platform Support**: This image is available for **linux/amd64 only**. ARM64 (Apple Silicon) is not supported because several dependencies (gsort, mosdepth, duphold, and smoove itself) only provide precompiled x86_64 binaries.

smoove simplifies structural variant discovery by automatically handling:
- Read preprocessing and filtering
- LUMPY execution with optimal parameters
- Post-processing and genotyping
- VCF formatting and annotation

## Usage

### Docker

```bash
docker pull getwilds/smoove:latest
# or
docker pull getwilds/smoove:0.2.8

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/smoove:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/smoove:latest
# or
apptainer pull docker://getwilds/smoove:0.2.8

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/smoove:latest
```

### Example Commands

#### Basic smoove Usage (Single Sample)

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/smoove:latest \
  smoove call \
    --outdir /data/results \
    --name sample1 \
    --fasta /data/reference.fa \
    --genotype \
    /data/sample1.bam

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/smoove:latest \
  smoove call \
    --outdir /data/results \
    --name sample1 \
    --fasta /data/reference.fa \
    --genotype \
    /data/sample1.bam
```

#### Multi-sample Analysis

```bash
# Step 1: Call variants on each sample
for sample in sample1 sample2 sample3; do
  docker run --rm -v /path/to/data:/data getwilds/smoove:latest \
    smoove call \
      --outdir /data/results \
      --name $sample \
      --fasta /data/reference.fa \
      --genotype \
      /data/${sample}.bam
done

# Step 2: Merge sites across samples
docker run --rm -v /path/to/data:/data getwilds/smoove:latest \
  smoove merge \
    --name cohort \
    --fasta /data/reference.fa \
    --outdir /data/results \
    /data/results/*.genotyped.vcf.gz

# Step 3: Genotype merged sites in each sample
for sample in sample1 sample2 sample3; do
  docker run --rm -v /path/to/data:/data getwilds/smoove:latest \
    smoove genotype \
      --outdir /data/results \
      --name $sample \
      --fasta /data/reference.fa \
      --vcf /data/results/cohort.sites.vcf.gz \
      /data/${sample}.bam
done

# Step 4: Paste individual genotyped VCFs into a single cohort VCF
docker run --rm -v /path/to/data:/data getwilds/smoove:latest \
  smoove paste \
    --name cohort \
    /data/results/*.genotyped.vcf.gz
```

#### With Exclude Regions

```bash
# Using an exclude BED file (e.g., repetitive regions, centromeres)
docker run --rm -v /path/to/data:/data getwilds/smoove:latest \
  smoove call \
    --outdir /data/results \
    --name sample1 \
    --fasta /data/reference.fa \
    --exclude /data/exclude.bed \
    --genotype \
    /data/sample1.bam
```

#### Using Include Regions (Targeted Analysis)

```bash
# Restrict analysis to specific genomic regions
docker run --rm -v /path/to/data:/data getwilds/smoove:latest \
  smoove call \
    --outdir /data/results \
    --name sample1 \
    --fasta /data/reference.fa \
    --include /data/target_regions.bed \
    --genotype \
    /data/sample1.bam
```

## smoove Overview

smoove is a streamlined structural variant caller that wraps LUMPY and other tools to provide:

- **Automated preprocessing**: Handles discordant read extraction and split-read detection
- **Optimized parameters**: Uses empirically-determined optimal settings for LUMPY
- **Multi-sample support**: Designed for population-scale analysis
- **Quality filtering**: Built-in filtering for high-confidence calls
- **Standard output**: Produces properly formatted VCF files

### Key Advantages over Raw LUMPY

- **Simplified workflow**: Single command replaces complex multi-step LUMPY pipeline
- **Better performance**: Optimized parameters and filtering
- **Population calling**: Built-in support for joint calling across multiple samples
- **Quality control**: Automatic filtering and quality assessment
- **Maintenance**: Actively maintained with regular updates

### Structural Variants Detected

- **Deletions**: Loss of genomic segments (>50bp)
- **Duplications**: Tandem duplications and copy number gains
- **Inversions**: Genomic rearrangements where sequence is reversed
- **Translocations**: Movement of genomic segments between chromosomes
- **Complex events**: More complex structural rearrangements

### Input Requirements

- **Aligned BAM files**: BWA-MEM aligned reads (recommended)
- **Reference genome**: FASTA file used for alignment
- **BAM index files**: Required for efficient processing (.bai files)
- **Optional exclude regions**: BED file of regions to exclude from analysis
- **Optional include regions**: BED file to restrict analysis to specific regions

## Workflow Steps

smoove automates the following pipeline:

1. **Extract evidence**: Discordant pairs and split reads from BAM using lumpy_filter
2. **Filter reads**: Remove low-quality and spurious alignment signals
3. **Calculate statistics**: Determine insert size distributions and coverage metrics
4. **Call variants**: Run LUMPY with optimized parameters
5. **Genotype**: Determine genotypes at each variant site using svtyper
6. **Annotate**: Add depth information using duphold (if enabled)
7. **Format output**: Produce standardized VCF files

## Available Tools in Image

The smoove Docker image includes these bioinformatics tools:

- **smoove**: Main wrapper tool for structural variant calling
- **lumpy**: Core structural variant detection algorithm
- **lumpy_filter**: Preprocessing tool for extracting evidence reads
- **svtyper**: Structural variant genotyping tool
- **samtools**: BAM file manipulation and processing
- **bcftools**: VCF file manipulation and processing  
- **mosdepth**: Fast depth calculation for coverage analysis
- **duphold**: Structural variant depth annotation
- **gsort**: Genomic coordinate sorting utility

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 22.04 as the base image for stability
2. Adds metadata labels for documentation and attribution following WILDS standards
3. Installs system dependencies and build tools
4. Builds and installs htslib, samtools, and bcftools from source
5. Builds and installs LUMPY-SV from source (includes lumpy and lumpy_filter)
6. Downloads and installs pre-compiled binaries for gsort, mosdepth, and duphold
7. Installs Python dependencies and svtyper
8. Downloads the smoove binary from GitHub releases
9. Configures library paths and working directory
10. Performs cleanup to minimize image size

## Performance Considerations

- **Memory**: Typically requires 4-16GB RAM for human genome analysis
- **CPU**: Benefits from multiple cores (4-8 cores recommended)
- **Storage**: Temporary files can be large; ensure adequate disk space (2-3x BAM size)
- **I/O**: Fast storage recommended for large BAM files

## Limitations

- **svtools not included**: Due to Python 2/3 compatibility issues, svtools is not included in the current image. This mainly affects large cohort analysis (>100 samples).
- **Memory usage**: Can be memory-intensive for high-coverage samples
- **Repetitive regions**: May produce false positives in highly repetitive genomic regions

## Security Features

The smoove Docker images include:

- Minimal base image with only required dependencies
- Specific version pinning for reproducibility
- Regular security scanning and vulnerability reporting

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/smoove), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

## Related Tools

smoove works well with other structural variant callers in the WILDS ecosystem:

- **Manta**: Available as `getwilds/manta:1.6.0` for complementary SV calling
- **GATK**: Available for additional variant calling approaches
- **Samtools/BCFtools**: For BAM file processing and variant manipulation

## Citation

If you use smoove in your research, please cite:

> Pedersen, Brent S., et al. "smoove: structural-variant calling and genotyping with existing tools." Bioinformatics 35.24 (2019): 4778-4780.

Also cite the underlying LUMPY algorithm:

> Layer, Ryan M., et al. "LUMPY: a probabilistic framework for structural variant discovery." Genome biology 15.6 (2014): R84.
