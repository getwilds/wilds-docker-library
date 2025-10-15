# Strelka

This directory contains Docker images for Strelka, a fast and accurate small variant caller optimized for analysis of germline variation in small cohorts and somatic variation in tumor/normal sample pairs.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/strelka/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/strelka/CVEs_latest.md) )
- `2.9.10` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/strelka/Dockerfile_2.9.10) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/strelka/CVEs_2.9.10.md) )

## Image Details

These Docker images are built from Ubuntu 22.04 and include:

- **Strelka v2.9.10**: Fast and accurate small variant caller with optimized algorithms for germline and somatic variant detection
- **samtools v1.19.2**: Suite of programs for interacting with high-throughput sequencing data
- **bcftools v1.19**: Utilities for variant calling and manipulating VCF/BCF files
- **htslib v1.19.1**: High-throughput sequencing data processing library
- **Python 2**: Required runtime environment for Strelka workflow configuration scripts
- **Python 3**: Available for additional scripting and analysis tasks

The images provide a complete environment for Strelka variant calling workflows with all necessary dependencies, built with version pinning and minimal package installation for security and reproducibility.

**Platform Support**: This image is available for **linux/amd64 only**. ARM64 (Apple Silicon) is not supported because Strelka only provides precompiled x86_64 binaries and building from source for ARM64 would require significant additional complexity.

## Usage

### Docker

```bash
docker pull getwilds/strelka:latest
# or
docker pull getwilds/strelka:2.9.10

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/strelka:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/strelka:latest
# or
apptainer pull docker://getwilds/strelka:2.9.10

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/strelka:latest
```

## Example Commands

### Germline Variant Calling

```bash
# Configure germline workflow
docker run --rm -v /path/to/data:/data getwilds/strelka:latest \
  configureStrelkaGermlineWorkflow.py \
  --bam /data/sample.bam \
  --referenceFasta /data/reference.fa \
  --runDir /data/strelka_germline

# Run the analysis
docker run --rm -v /path/to/data:/data getwilds/strelka:latest \
  /data/strelka_germline/runWorkflow.py -m local -j 4
```

### Somatic Variant Calling (Tumor/Normal Pairs)

```bash
# Configure somatic workflow
docker run --rm -v /path/to/data:/data getwilds/strelka:latest \
  configureStrelkaSomaticWorkflow.py \
  --normalBam /data/normal.bam \
  --tumorBam /data/tumor.bam \
  --referenceFasta /data/reference.fa \
  --runDir /data/strelka_somatic

# Run the analysis
docker run --rm -v /path/to/data:/data getwilds/strelka:latest \
  /data/strelka_somatic/runWorkflow.py -m local -j 4
```

### Apptainer Examples

```bash
# Germline workflow configuration
apptainer run --bind /path/to/data:/data docker://getwilds/strelka:latest \
  configureStrelkaGermlineWorkflow.py \
  --bam /data/sample.bam \
  --referenceFasta /data/reference.fa \
  --runDir /data/strelka_germline

# Somatic workflow configuration
apptainer run --bind /path/to/data:/data docker://getwilds/strelka:latest \
  configureStrelkaSomaticWorkflow.py \
  --normalBam /data/normal.bam \
  --tumorBam /data/tumor.bam \
  --referenceFasta /data/reference.fa \
  --runDir /data/strelka_somatic
```

## Available Strelka Workflows

Strelka provides several workflow configuration scripts:

- **configureStrelkaGermlineWorkflow.py**: Configure germline small variant calling
- **configureStrelkaSomaticWorkflow.py**: Configure somatic small variant calling for tumor/normal pairs
- **configureStrelkaDenovoWorkflow.py**: Configure de novo variant calling in family trios

Each workflow creates a run directory with a `runWorkflow.py` script that executes the actual analysis.

## Key Strelka Parameters

### Germline Workflow Options
- `--bam`: Input BAM/CRAM file(s)
- `--referenceFasta`: Reference genome in FASTA format
- `--runDir`: Directory where the workflow will be configured and run
- `--region`: Restrict analysis to specified region(s)
- `--exome`: Set configuration defaults for exome sequencing

### Somatic Workflow Options
- `--normalBam`: Normal sample BAM/CRAM file
- `--tumorBam`: Tumor sample BAM/CRAM file
- `--referenceFasta`: Reference genome in FASTA format
- `--runDir`: Directory where the workflow will be configured and run
- `--region`: Restrict analysis to specified region(s)
- `--exome`: Set configuration defaults for exome sequencing
- `--callRegions`: BED file specifying regions to call variants

### Runtime Options
- `-m local`: Run workflow locally (single machine)
- `-j N`: Number of parallel jobs to run
- `--quiet`: Suppress workflow status updates

## Output Files

Strelka generates several output files in the specified run directory:

### Germline Analysis
- `results/variants/variants.vcf.gz`: All variant calls
- `results/variants/genome.S1.vcf.gz`: Filtered high-confidence variants

### Somatic Analysis
- `results/variants/somatic.snvs.vcf.gz`: Somatic SNV calls
- `results/variants/somatic.indels.vcf.gz`: Somatic indel calls
- `results/variants/germline.snvs.vcf.gz`: Germline SNV calls
- `results/variants/germline.indels.vcf.gz`: Germline indel calls

## Performance Considerations

- Strelka is optimized for speed and can process whole genome samples in hours
- Memory usage is typically low (< 2GB for most analyses)
- CPU scaling is effective up to ~8-16 cores for most datasets
- For large cohorts, consider using workflow managers like Nextflow or Snakemake

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 22.04 as the base image for broad compatibility
2. Adds metadata labels for documentation and attribution
3. Configures shell with pipefail for better error handling
4. Installs system dependencies with version pinning and minimal recommendations
5. Builds and installs htslib v1.19.1, samtools v1.19.2, and bcftools v1.19 from source
6. Downloads and installs Strelka v2.9.10 pre-compiled binaries
7. Installs both Python 2 (required for Strelka) and Python 3 (for additional functionality)
8. Performs cleanup to minimize image size and reduce attack surface

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/strelka), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

## Additional Resources

- [Strelka Official Documentation](https://github.com/Illumina/strelka/blob/v2.9.x/docs/userGuide/README.md)
- [Strelka GitHub Repository](https://github.com/Illumina/strelka)
- [Strelka Publication](https://www.nature.com/articles/nmeth.4227)
- [Illumina BaseSpace Strelka App](https://basespace.illumina.com/apps/2150838/Strelka-Germline-and-Somatic-Small-Variant-Caller)

## License

This Docker image packages open-source software. Strelka is distributed under the GPLv3 license.
