# ichorCNA

This directory contains Docker images for ichorCNA, a tool for estimating the fraction of tumor in cell-free DNA.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/ichorcna/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/ichorcna/CVEs_latest.md) )
- `0.2.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/ichorcna/Dockerfile_0.2.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/ichorcna/CVEs_0.2.0.md) )

## Image Details

These Docker images are built from Ubuntu 20.04 and include:

- **ichorCNA v0.2.0 at b2bbce0**: An R tool for estimating tumor fraction of cfDNA
- **R v3.6.0**: Statistical computing environment compiled from source
- **HMMcopy**: Bioconductor package for copy number analysis using hidden Markov models
- **GenomeInfoDb & GenomicRanges**: Bioconductor packages for genomic data manipulation
- **Data processing R packages**: plyr, optparse, foreach, doMC for data processing and parallel computing
- **BiocManager**: Package manager for Bioconductor repositories

The images are designed to be comprehensive yet minimal, providing essential tools for a workflow using ichorCNA.

## Usage

### Docker

```bash
docker pull getwilds/ichorcna:latest
# or
docker pull getwilds/ichorcna:0.2.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/ichorcna:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/ichorcna:latest
# or
apptainer pull docker://getwilds/ichorcna:0.2.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/ichorcna:latest
```

### Example Commands

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/ichorcna:latest \
  Rscript /usr/local/bin/ichorCNA/scripts/runIchorCNA.R \
    --id "SampleID" \
    --WIG "SampleID.ichor.tumor.wig" \
    --ploidy "c(2)" \
    --normal "c(0.1,0.5,.85)" \
    --maxCN 3 \
    --gcWig "gc_hg38_500kb.wig" \
    --mapWig "map_hg38_500kb.wig" \
    --centromere "GRCh38.GCA_000001405.2_centromere_acen.txt" \
    --normalPanel "nextera_hg38_500kb_median_normAutosome_median.rds_median.n9.gr.rds" \
    --genomeBuild "hg38" \
    --sex "male" \
    --fracReadsInChrYForMale 0.0005 \
    --txnE 0.999999 \
    --txnStrength 1000000 \
    --genomeStyle "UCSC" \
    --libdir /usr/local/bin/ichorCNA/

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/ichorcna:latest \
  Rscript /usr/local/bin/ichorCNA/scripts/runIchorCNA.R \
    --id "SampleID" \
    --WIG "SampleID.ichor.tumor.wig" \
    --ploidy "c(2)" \
    --normal "c(0.1,0.5,.85)" \
    --maxCN 3 \
    --gcWig "gc_hg38_500kb.wig" \
    --mapWig "map_hg38_500kb.wig" \
    --centromere "GRCh38.GCA_000001405.2_centromere_acen.txt" \
    --normalPanel "nextera_hg38_500kb_median_normAutosome_median.rds_median.n9.gr.rds" \
    --genomeBuild "hg38" \
    --sex "male" \
    --fracReadsInChrYForMale 0.0005 \
    --txnE 0.999999 \
    --txnStrength 1000000 \
    --genomeStyle "UCSC" \
    --libdir /usr/local/bin/ichorCNA/
```

## Key Features

### **ichorCNA**
- **Run ichorCNA**: Using `runIchorCNA.R`
- **Create Panel of Normals**: Using `createPanelOfNormals.R`

### **Supporting Tools**
- **HMMcopy**: Generate read count files

### **Compatibility**
- **Input formats**: BAM, WIG
- **Reference genomes**: Human
- **Workflow engines**: Compatible with WDL, Nextflow, Snakemake

## Performance Considerations

### Resource Requirements
- **Memory**: 4-32 GB recommended for copy number analysis and tumor fraction estimation
- **CPU**: Multi-threaded operations supported via doMC parallel processing
- **Storage**: Ensure sufficient space for output files and temporary data

### Optimization Tips
- For < 5% expected tumor fraction, it may be helpful to modify the settings
    - See the relevant [wiki page](https://github.com/broadinstitute/ichorCNA/wiki/Parameter-tuning-and-settings) for this version of ichorCNA

## Security Features

The ichorDNA Docker images include:

- Dynamic versioning for build-essential to ensure the latest security patches
- Installation through Ubuntu package repositories for properly vetted binaries
- Minimal installation with only required dependencies

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/bedtools), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure
The Dockerfile follows these main steps:

1. Uses Ubuntu 20.04 as the base image
2. Adds metadata labels for documentation and attribution following WILDS standards
3. Dynamically determines and pins the latest security-patched version of build-essential
4. Downloads and installs R 3.6.0 from source
5. Installs required R packages from CRAN and Bioconductor repositories
6. Clones and installs IchorCNA from GitHub
7. Cleans up temporary files and build artifacts to minimize image size

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
