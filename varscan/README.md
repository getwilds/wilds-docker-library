# VarScan

This directory contains Docker images for VarScan, a platform-independent variant caller for detecting SNVs and indels in NGS data using heuristic/statistical approaches.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/varscan/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/varscan/CVEs_latest.md) )
- `2.4.6` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/varscan/Dockerfile_2.4.6) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/varscan/CVEs_2.4.6.md) )

## Image Details

These Docker images are built from Ubuntu 22.04 and include:

- **VarScan v2.4.6**: Platform-independent variant caller for germline and somatic variant detection
- **SAMtools v1.19**: Suite of programs for interacting with high-throughput sequencing data  
- **bcftools v1.19**: Utilities for variant calling and manipulating VCF/BCF files
- **htslib v1.19**: High-throughput sequencing data processing library
- **vcftools**: VCF file manipulation utilities including vcf-sort
- **Java 8**: Required runtime environment for VarScan

The images are designed to provide a complete environment for VarScan variant calling workflows with all necessary dependencies, built with version pinning and minimal package installation for security and reproducibility.

## Usage

### Docker

```bash
docker pull getwilds/varscan:latest
# or
docker pull getwilds/varscan:2.4.6

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/varscan:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/varscan:latest
# or
apptainer pull docker://getwilds/varscan:2.4.6

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/varscan:latest
```

## Example Commands

### Basic Germline Variant Calling

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/varscan:latest \
  sh -c "samtools mpileup -f /data/reference.fa /data/sample.bam | \
         java -jar /usr/local/bin/VarScan.jar mpileup2snp \
         --min-coverage 8 --min-var-freq 0.01 --p-value 0.99 \
         --output-vcf 1 > /data/variants.vcf"

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/varscan:latest \
  sh -c "samtools mpileup -f /data/reference.fa /data/sample.bam | \
         java -jar /usr/local/bin/VarScan.jar mpileup2snp \
         --min-coverage 8 --min-var-freq 0.01 --p-value 0.99 \
         --output-vcf 1 > /data/variants.vcf"
```

### Somatic Mutation Calling (Tumor-Normal Pairs)

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/varscan:latest \
  sh -c "samtools mpileup -f /data/reference.fa /data/normal.bam /data/tumor.bam | \
         java -jar /usr/local/bin/VarScan.jar somatic \
         /dev/stdin /data/output_prefix \
         --min-coverage 8 --min-var-freq 0.10 --somatic-p-value 0.05 \
         --output-vcf 1"

# Apptainer  
apptainer run --bind /path/to/data:/data docker://getwilds/varscan:latest \
  sh -c "samtools mpileup -f /data/reference.fa /data/normal.bam /data/tumor.bam | \
         java -jar /usr/local/bin/VarScan.jar somatic \
         /dev/stdin /data/output_prefix \
         --min-coverage 8 --min-var-freq 0.10 --somatic-p-value 0.05 \
         --output-vcf 1"
```

### Trio Calling (Family-Based Analysis)

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/varscan:latest \
  sh -c "samtools mpileup -f /data/reference.fa /data/father.bam /data/mother.bam /data/child.bam | \
         java -jar /usr/local/bin/VarScan.jar trio \
         /dev/stdin /data/family_output \
         --min-coverage 8 --min-var-freq 0.20 \
         --output-vcf 1"

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/varscan:latest \
  sh -c "samtools mpileup -f /data/reference.fa /data/father.bam /data/mother.bam /data/child.bam | \
         java -jar /usr/local/bin/VarScan.jar trio \
         /dev/stdin /data/family_output \
         --min-coverage 8 --min-var-freq 0.20 \
         --output-vcf 1"
```

### Using VarScan Directly

VarScan can be called directly using the Java JAR file:

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/varscan:latest \
  java -jar /usr/local/bin/VarScan.jar mpileup2snp --help

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/varscan:latest \
  java -jar /usr/local/bin/VarScan.jar mpileup2snp --help
```

## VarScan Modules

VarScan provides several modules for different types of variant calling:

- **mpileup2snp**: Call SNPs from mpileup data
- **mpileup2indel**: Call indels from mpileup data  
- **mpileup2cns**: Call consensus genotype from mpileup data
- **somatic**: Call somatic mutations in tumor-normal pairs
- **trio**: Call variants in family trios with inheritance information
- **copynumber**: Determine relative copy number from tumor-normal pairs
- **readcounts**: Obtain read counts for a list of variants
- **filter**: Filter variant calls based on coverage, frequency, etc.
- **somaticFilter**: Apply filtering specifically for somatic variants
- **processSomatic**: Separate somatic variants into high/low confidence
- **fpfilter**: Apply false-positive filters to variant calls

## Key VarScan Parameters

### Coverage and Quality
- `--min-coverage`: Minimum read depth at a position to make a call (default: 8)
- `--min-avg-qual`: Minimum average quality of variant-supporting reads (default: 15)
- `--min-reads2`: Minimum supporting reads at a position to call variants (default: 2)

### Allele Frequency  
- `--min-var-freq`: Minimum variant allele frequency threshold (default: 0.01)
- `--min-freq-for-hom`: Minimum frequency to call homozygote (default: 0.75)

### Statistical Significance
- `--p-value`: P-value threshold for calling variants (default: 0.99)
- `--somatic-p-value`: P-value threshold for somatic calls (default: 0.05)

### Output Options
- `--output-vcf 1`: Output variants in VCF format
- `--vcf-sample-list`: File containing sample names for VCF header

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 22.04 as the base image for broad compatibility
2. Adds metadata labels for documentation and attribution
3. Configures shell with pipefail for better error handling
4. Installs system dependencies with version pinning and minimal recommendations
5. Builds and installs htslib v1.19, samtools v1.19, and bcftools v1.19 from source
6. Downloads VarScan v2.4.6 JAR file
7. Performs cleanup to minimize image size and reduce attack surface

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/varscan), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

## Additional Resources

- [VarScan Official Website](http://varscan.sourceforge.net/)
- [VarScan GitHub Repository](https://github.com/dkoboldt/varscan)
- [VarScan User Manual](http://varscan.sourceforge.net/using-varscan.html)
- [Using VarScan 2 for Germline Variant Calling and Somatic Mutation Detection](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC4278659/)

## License

This Docker image packages open-source software. VarScan is distributed under a non-commercial academic license. Please refer to the individual software licenses for details.
