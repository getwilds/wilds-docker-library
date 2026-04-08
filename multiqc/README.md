# MultiQC

This directory contains Docker images for [MultiQC](https://seqera.io/multiqc/), a tool for aggregating quality control results from bioinformatics analyses across many samples into a single interactive HTML report.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/multiqc/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/multiqc/CVEs_latest.md) )
- `1.33` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/multiqc/Dockerfile_1.33) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/multiqc/CVEs_1.33.md) )

## Image Details

These Docker images are built from `python:3.13-slim` and include:

- MultiQC v1.33: Aggregates results from 150+ bioinformatics tools into a single report
- procps: Process utilities (included for pipeline compatibility)

The images are designed to be minimal and focused on MultiQC with its essential dependencies.

## Citation

If you use MultiQC in your research, please cite the original authors:

```
Ewels P, Magnusson M, Lundin S, Kaller M. MultiQC: summarize analysis results
for multiple tools and samples in a single report. Bioinformatics. 2016;32(19):3047-3048.
doi:10.1093/bioinformatics/btw354
```

**Tool homepage:** https://seqera.io/multiqc/

**Publication:** https://doi.org/10.1093/bioinformatics/btw354

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/multiqc:latest

# Or pull a specific version
docker pull getwilds/multiqc:1.33

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/multiqc:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/multiqc:latest

# Or pull a specific version
apptainer pull docker://getwilds/multiqc:1.33

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/multiqc:latest
```

### Example Commands

```bash
# Generate a report from all tool outputs in a directory
docker run --rm -v /path/to/data:/data getwilds/multiqc:latest \
  multiqc /data --outdir /data/multiqc_report

# Generate a report with a custom title
docker run --rm -v /path/to/data:/data getwilds/multiqc:latest \
  multiqc /data --outdir /data/multiqc_report --title "My Experiment QC"

# Run on specific directories only
docker run --rm -v /path/to/data:/data getwilds/multiqc:latest \
  multiqc /data/fastqc /data/star --outdir /data/multiqc_report

# Generate a flat image report (no interactive plots)
docker run --rm -v /path/to/data:/data getwilds/multiqc:latest \
  multiqc /data --flat --outdir /data/multiqc_report

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/multiqc:latest \
  multiqc /data --outdir /data/multiqc_report
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `python:3.13-slim` as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system dependencies (procps) with pinned versions
4. Installs MultiQC via pip with `--no-cache-dir`
5. Runs a smoke test to verify the installation

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/multiqc), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

---
