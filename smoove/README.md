# smoove

This directory contains Docker images for smoove, a streamlined workflow for structural variant calling and genotyping using LUMPY and other established tools.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/smoove/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/smoove/CVEs_latest.md) )
- `0.2.8` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/smoove/Dockerfile_0.2.8) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/smoove/CVEs_0.2.8.md) )

## Image Details

These Docker images are built from Ubuntu 22.04 and include:

- smoove v0.2.8: A streamlined workflow that wraps LUMPY, samtools, and other tools
- All dependencies bundled in the single binary for easy deployment

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
    /data/sample1.bam

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/smoove:latest \
  smoove call \
    --outdir /data/results \
    --name sample1 \
    --fasta /data/reference.fa \
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
      /data/${sample}.bam
done

# Step 2: Merge and genotype across all samples
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
    --outdir /data/results \
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
    --excludechroms "~^HLA,~^hs,~random,~chrUn,~_alt,~chrEBV" \
    --exclude /data/exclude.bed \
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
- **BAM index files**: Required for efficient processing
- **Optional exclude regions**: BED file of regions to exclude from analysis

## Workflow Steps

smoove automates the following pipeline:

1. **Extract evidence**: Discordant pairs and split reads from BAM
2. **Call variants**: Run LUMPY with optimized parameters
3. **Genotype**: Determine genotypes at each variant site
4. **Filter**: Apply quality filters and remove low-confidence calls
5. **Annotate**: Add additional information to VCF records

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 22.04 as the base image for stability
2. Adds metadata labels for documentation and attribution following WILDS standards
3. Installs minimal dependencies (wget, curl, bzip2)
4. Downloads the pre-compiled smoove binary from GitHub releases
5. Sets up executable permissions and PATH
6. Configures working directory
7. Performs cleanup to minimize image size

## Performance Considerations

- **Memory**: Typically requires 4-8GB RAM for human genome analysis
- **CPU**: Benefits from multiple cores (4-8 cores recommended)
- **Storage**: Temporary files can be large; ensure adequate disk space
- **I/O**: Fast storage recommended for large BAM files

## Security Features

The smoove Docker images include:

- Minimal base image with only required dependencies
- Pre-compiled binary reduces build complexity and security surface
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

This directory contains Docker images for LUMPY (Layer Upon Layer of Multiple Paired-end), a general probabilistic framework for structural variant discovery.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/lumpy/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/lumpy/CVEs_latest.md) )
- `0.3.1` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/lumpy/Dockerfile_0.3.1) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/lumpy/CVEs_0.3.1.md) )

## Image Details

These Docker images are built from Ubuntu 22.04 and include:

- LUMPY v0.3.1: A probabilistic framework for structural variant discovery
- HTSlib v1.19.1: High-throughput sequencing data processing library
- Samtools v1.19.2: Suite of programs for interacting with SAM/BAM files
- Python 3 with pysam: For running LUMPY's Python helper scripts

The images are designed to be minimal and focused on LUMPY with its required dependencies for structural variant calling.

## Usage

### Docker

```bash
docker pull getwilds/lumpy:latest
# or
docker pull getwilds/lumpy:0.3.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/lumpy:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/lumpy:latest
# or
apptainer pull docker://getwilds/lumpy:0.3.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/lumpy:latest
```

### Example Commands

#### Basic LUMPY Usage

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/lumpy:latest \
  lumpy \
    -mw 4 \
    -tt 0 \
    -pe bam_file:/data/sample.bam,histo_file:/data/sample.histo,mean:500,stdev:50,read_length:100,min_non_overlap:101,discordant_z:5,back_distance:10,weight:1,id:1 \
    -sr bam_file:/data/sample.bam,back_distance:10,weight:1,id:1,min_mapping_threshold:20 \
    > /data/sample.vcf

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/lumpy:latest \
  lumpy \
    -mw 4 \
    -tt 0 \
    -pe bam_file:/data/sample.bam,histo_file:/data/sample.histo,mean:500,stdev:50,read_length:100,min_non_overlap:101,discordant_z:5,back_distance:10,weight:1,id:1 \
    -sr bam_file:/data/sample.bam,back_distance:10,weight:1,id:1,min_mapping_threshold:20 \
    > /data/sample.vcf
```

#### Using LUMPY Express (Simplified Workflow)

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/lumpy:latest \
  lumpyexpress \
    -B /data/sample.bam \
    -S /data/sample.splitters.bam \
    -D /data/sample.discordants.bam \
    -o /data/sample.vcf

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/lumpy:latest \
  lumpyexpress \
    -B /data/sample.bam \
    -S /data/sample.splitters.bam \
    -D /data/sample.discordants.bam \
    -o /data/sample.vcf
```

#### Preprocessing Steps

LUMPY requires preprocessing to extract discordant and split reads:

```bash
# Extract discordant read pairs
docker run --rm -v /path/to/data:/data getwilds/lumpy:latest \
  samtools view -b -F 1294 /data/sample.bam > /data/sample.discordants.unsorted.bam

# Extract split reads
docker run --rm -v /path/to/data:/data getwilds/lumpy:latest \
  samtools view -h /data/sample.bam | \
  /opt/lumpy-sv/scripts/extractSplitReads_BwaMem -i stdin | \
  samtools view -Sb - > /data/sample.splitters.unsorted.bam

# Sort the BAM files
docker run --rm -v /path/to/data:/data getwilds/lumpy:latest \
  samtools sort /data/sample.discordants.unsorted.bam > /data/sample.discordants.bam

docker run --rm -v /path/to/data:/data getwilds/lumpy:latest \
  samtools sort /data/sample.splitters.unsorted.bam > /data/sample.splitters.bam
```

## LUMPY Overview

LUMPY is a structural variant caller that uses multiple signals to detect:

- **Deletions**: Loss of genomic segments
- **Duplications**: Tandem duplications and copy number gains
- **Inversions**: Genomic rearrangements where sequence is reversed
- **Translocations**: Movement of genomic segments between chromosomes
- **Complex rearrangements**: More complex structural changes

### Key Features

- **Multi-evidence approach**: Combines paired-end, split-read, and read-depth signals
- **Probabilistic framework**: Uses statistical modeling for confident variant calls
- **Flexible input**: Supports various evidence types and can integrate multiple samples
- **Speed**: Optimized for large-scale genomic analyses

### Input Requirements

- **Aligned BAM files**: Primary input containing mapped reads
- **Discordant reads**: Read pairs with unexpected insert sizes or orientations
- **Split reads**: Reads that align partially to multiple genomic locations
- **Optional**: Read-depth information for copy number analysis

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 22.04 as the base image for stability
2. Adds metadata labels for documentation and attribution following WILDS standards
3. Installs build dependencies and development tools
4. Builds and installs HTSlib from source
5. Builds and installs Samtools from source
6. Clones and builds LUMPY from the official repository
7. Installs Python dependencies for helper scripts
8. Configures PATH and working directory
9. Performs cleanup to minimize image size

## Security Features

The LUMPY Docker images include:

- Minimal base image with only required dependencies
- Specific version pinning for reproducibility
- Regular security scanning and vulnerability reporting

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/lumpy), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

## Related Tools

LUMPY works well with other structural variant callers in the WILDS ecosystem:

- **Manta**: Available as `getwilds/manta:1.6.0` for complementary SV calling
- **GATK**: Available for additional variant calling approaches
- **Samtools/BCFtools**: For BAM file processing and variant manipulation

## Citation

If you use LUMPY in your research, please cite:

> Layer, Ryan M., et al. "LUMPY: a probabilistic framework for structural variant discovery." Genome biology 15.6 (2014): R84.
