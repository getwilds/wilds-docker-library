# FastQC

This directory contains Docker images for FastQC, a quality control tool for high throughput sequence data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/fastqc/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/fastqc/CVEs_latest.md) )
- `0.12.1` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/fastqc/Dockerfile_0.12.1) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/fastqc/CVEs_0.12.1.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- **FastQC v0.12.1**: A quality control tool that provides a simple way to do some quality control checks on raw sequence data
- **OpenJDK 11**: The Java runtime environment required to run FastQC
- **Perl**: Required for FastQC's internal operations

The images are designed to be minimal and focused on FastQC with its essential dependencies.

## Usage

### Docker

```bash
docker pull getwilds/fastqc:latest
# or
docker pull getwilds/fastqc:0.12.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/fastqc:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/fastqc:latest
# or
apptainer pull docker://getwilds/fastqc:0.12.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/fastqc:latest
```

### Example Commands

```bash
# Analyze a single FASTQ file
docker run --rm -v /path/to/data:/data getwilds/fastqc:latest fastqc /data/sample.fastq.gz --outdir=/data

# Analyze multiple FASTQ files
docker run --rm -v /path/to/data:/data getwilds/fastqc:latest fastqc /data/*.fastq.gz --outdir=/data

# Run with custom parameters
docker run --rm -v /path/to/data:/data getwilds/fastqc:latest fastqc /data/sample.fastq.gz --outdir=/data --threads 4 --extract

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/fastqc:latest fastqc /data/sample.fastq.gz --outdir=/data

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data fastqc_latest.sif fastqc /data/*.fastq.gz --outdir=/data --threads 4
```

## Key Features

### **Quality Control Modules**
- **Basic Statistics**: Sequence count, length distribution, GC content
- **Per Base Sequence Quality**: Quality scores across all bases
- **Per Tile Sequence Quality**: Quality scores for each tile across all sequences
- **Per Sequence Quality Scores**: Distribution of quality score averages
- **Per Base Sequence Content**: Proportion of each base position for which each of the four normal DNA bases has been called
- **Per Sequence GC Content**: GC content across the whole length of each sequence
- **Per Base N Content**: Percentage of base calls at each position for which an N was called
- **Sequence Length Distribution**: Distribution of fragment sizes
- **Sequence Duplication Levels**: Relative level of duplication found for every sequence
- **Overrepresented Sequences**: Sequences which make up more than 0.1% of the total
- **Adapter Content**: Cumulative percentage count of the proportion of your library which has seen each of the adapter sequences at each position

### **Output Formats**
- **HTML Report**: Comprehensive visual report with graphs and summaries
- **ZIP Archive**: Contains all data files and images used in the HTML report
- **Text Summary**: Tab-delimited summary file for programmatic analysis

### **Input Format Support**
- **FASTQ**: Standard and compressed (.gz, .bz2)
- **SAM/BAM**: Sequence alignment files
- **Colorspace**: SOLiD sequencing data

## Performance Considerations

### Resource Requirements
- **Memory**: 1-4GB recommended depending on file size
- **CPU**: Multi-threaded processing supported via `--threads` parameter
- **Storage**: Ensure sufficient space for output HTML and ZIP files

### Optimization Tips
- Use `--threads` parameter to utilize multiple CPU cores for faster processing
- Process multiple files in parallel for batch analysis
- Use `--extract` flag to automatically extract ZIP archives for easier access to individual result files
- Consider using `--quiet` flag for automated workflows to reduce output verbosity

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/fastqc), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Dynamically determines and pins the latest security-patched versions of dependencies
4. Downloads FastQC from the official Babraham Bioinformatics repository
5. Makes FastQC executable and creates a symbolic link for easy access
6. Performs cleanup to minimize image size

## Citation

If you use FastQC in your research, please cite the original software:

> Andrews S. (2010). FastQC: a quality control tool for high throughput sequence data. Available online at: http://www.bioinformatics.babraham.ac.uk/projects/fastqc

FastQC was developed by Simon Andrews at the [Babraham Bioinformatics](http://www.bioinformatics.babraham.ac.uk/) group.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.