# GATK

This directory contains Docker images for the Genome Analysis Toolkit (GATK), a software package developed by the Broad Institute for analyzing high-throughput sequencing data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/gatk/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/gatk/CVEs_latest.md) )
- `4.6.1.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/gatk/Dockerfile_4.6.1.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/gatk/CVEs_4.6.1.0.md) )
- `4.3.0.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/gatk/Dockerfile_4.3.0.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/gatk/CVEs_4.3.0.0.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- **GATK 4.6.1.0**: A toolkit for variant discovery in high-throughput sequencing data
- **Samtools 1.20**: A suite of programs for interacting with high-throughput sequencing data
- **htslib 1.20**: High-throughput sequencing library including bgzip and tabix utilities
- **Java 17**: Required runtime environment for GATK
- **Python 3**: For GATK workflow scripts and utilities
- **GNU Parallel**: For parallel execution of tasks

The images are designed to be comprehensive yet minimal, providing all essential tools for genomics analysis workflows.

## Platform Availability

**Note:** This image is only built for **linux/amd64** architecture. GATK's official release bundles the GenomicsDB (`libtiledbgenomicsdb.so`) and Intel GKL native libraries as x86_64-only binaries, with no ARM64 variant provided upstream. Tools that depend on GenomicsDB, such as `GenomicsDBImport` and `CreateSomaticPanelOfNormals`, fail at runtime on ARM64 hosts even when the image itself builds successfully, so ARM64 images are not published for this tool.

## Usage

### Docker

```bash
docker pull getwilds/gatk:latest
# or
docker pull getwilds/gatk:4.6.1.0
# or
docker pull getwilds/gatk:4.3.0.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/gatk:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/gatk:latest
# or
apptainer pull docker://getwilds/gatk:4.6.1.0
# or
apptainer pull docker://getwilds/gatk:4.3.0.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/gatk:latest
```

### Example Commands

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/gatk:latest gatk HaplotypeCaller \
  -R /data/reference.fa -I /data/input.bam -O /data/output.vcf

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/gatk:latest gatk HaplotypeCaller \
  -R /data/reference.fa -I /data/input.bam -O /data/output.vcf
```

## Key Features

### **GATK Tools**
- **Variant Calling**: HaplotypeCaller, Mutect2, GenotypeGVCFs
- **Data Processing**: MarkDuplicates, BaseRecalibrator, ApplyBQSR
- **Quality Control**: CollectMetrics, ValidateSamFile
- **Utilities**: SelectVariants, VariantFiltration, MergeVcfs

### **Supporting Tools**
- **samtools**: BAM/SAM/CRAM file manipulation and analysis
- **bgzip**: Block compression for genomics files
- **tabix**: Fast indexing and retrieval for compressed genomics files
- **htslib utilities**: Additional tools for high-throughput sequencing data

### **Compatibility**
- **Input formats**: BAM, SAM, CRAM, VCF, GVCF, BED
- **Reference genomes**: Human, mouse, and custom assemblies
- **Workflow engines**: Compatible with WDL, Nextflow, Snakemake

## Performance Considerations

### **Resource Requirements**
- **Memory**: 8-32GB recommended depending on genome size and tool
- **CPU**: Most tools benefit from multiple cores
- **Storage**: Ensure sufficient space for intermediate files

### **Optimization Tips**
- Use interval lists for targeted sequencing to improve performance
- Consider parallel processing for large cohorts using GNU Parallel
- Use appropriate Java memory settings with `--java-options`

## Security Features

The GATK Docker images include:

- **Multi-stage build**: Keeps compilers and development headers out of the final image
- **Source compilation**: Built from source for optimal performance and security
- **Pinned versions**: Specific versions for reproducibility in both stages
- **Minimal installation**: Only required runtime dependencies included
- **Regular updates**: Images updated with latest security patches

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/gatk), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile uses a multi-stage build to keep the final image minimal:

1. **Build stage**: Uses Ubuntu 24.04 with build tools and dev headers to download GATK 4.6.1.0 and compile htslib 1.20 (bgzip, tabix) and samtools 1.20 from source
2. **Final stage**: Uses a fresh Ubuntu 24.04 base with only the runtime libraries needed to run GATK and the compiled binaries
3. Adds metadata labels for documentation and attribution
4. Dynamically determines and pins the latest security-patched versions of dependencies in both stages
5. Copies GATK and the compiled samtools/htslib binaries from the build stage
6. Verifies all installations with a smoke test

This approach keeps compilers and development headers out of the final image, reducing its size and attack surface.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
