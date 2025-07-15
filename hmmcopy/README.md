# HMMcopy

This directory contains Docker images for HMMcopy utilities, providing tools for copy number analysis including read counting for downstream analysis with ichorCNA.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/hmmcopy/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/hmmcopy/CVEs_latest.md) )
- `1.0.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/hmmcopy/Dockerfile_1.0.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/hmmcopy/CVEs_1.0.0.md) )

## Image Details

These Docker images are built from Ubuntu 20.04 and include:

- **HMMcopy utilities**: Complete suite of command-line tools for copy number analysis
- **readCounter**: Tool for generating windowed read counts from BAM files
- **gcCounter**: Tool for calculating GC content in genomic windows
- **mapCounter**: Tool for calculating mappability scores in genomic windows
- **Build tools**: Essential compilation tools for building from source

The images are designed to be minimal yet comprehensive, providing the core HMMcopy utilities commonly used in copy number variation analysis workflows.

## Usage

### Docker

```bash
docker pull getwilds/hmmcopy:latest
# or
docker pull getwilds/hmmcopy:1.0.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/hmmcopy:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/hmmcopy:latest
# or
apptainer pull docker://getwilds/hmmcopy:1.0.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/hmmcopy:latest
```

### Example Commands

```bash
# Docker - Generate read counts for ichorCNA
docker run --rm -v /path/to/data:/data getwilds/hmmcopy:latest \
  readCounter \
    --window 500000 \
    --quality 20 \
    --chromosome 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,X,Y \
    /data/sample.bam > /data/sample.wig

# Generate GC content file
docker run --rm -v /path/to/data:/data getwilds/hmmcopy:latest \
  gcCounter \
    --window 500000 \
    --chromosome 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,X,Y \
    /data/reference.fa > /data/gc_content.wig

# Generate mappability file
docker run --rm -v /path/to/data:/data getwilds/hmmcopy:latest \
  mapCounter \
    --window 500000 \
    --chromosome 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,X,Y \
    /data/mappability.bw > /data/mappability.wig

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/hmmcopy:latest \
  readCounter \
    --window 500000 \
    --quality 20 \
    --chromosome 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,X,Y \
    /data/sample.bam > /data/sample.wig
```

## Key Features

### **Core Utilities**
- **readCounter**: Generate windowed read depth from BAM files
- **gcCounter**: Calculate GC content in genomic windows
- **mapCounter**: Calculate mappability scores in genomic windows

### **Integration**
- **ichorCNA compatibility**: Optimized for generating input files for ichorCNA workflows
- **Copy number analysis**: Standard tools for preprocessing data for HMM-based copy number calling

### **Compatibility**
- **Input formats**: BAM, FASTA, BigWig
- **Reference genomes**: Human and other species
- **Workflow engines**: Compatible with WDL, Nextflow, Snakemake

## Performance Considerations

### Resource Requirements
- **Memory**: 4-8 GB recommended for most analyses
- **CPU**: Single-threaded operations
- **Storage**: Ensure sufficient space for output WIG files

### Optimization Tips
- Use appropriate window sizes (500kb for low-resolution, 1kb for high-resolution analysis)
- Filter BAM files by mapping quality (--quality 20 recommended)
- Consider chromosome-specific analysis for large genomes

## Security Features

The HMMcopy Docker images include:

- Dynamic versioning for build-essential to ensure the latest security patches
- Installation through Ubuntu package repositories for properly vetted binaries
- Minimal installation with only required dependencies

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/hmmcopy), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure
The Dockerfile follows these main steps:

1. Uses Ubuntu 20.04 as the base image
2. Installs essential build tools (build-essential, cmake, zlib1g-dev, git, ca-certificates)
3. Clones the HMMcopy utilities source code from shahcompbio/hmmcopy_utils
4. Compiles the utilities using cmake and make
5. Installs binaries to /usr/local/bin for system-wide access
6. Cleans up build artifacts to minimize image size

The build process compiles all HMMcopy utilities from source, ensuring compatibility and optimal performance on the target architecture.
