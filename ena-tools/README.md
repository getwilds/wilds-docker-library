# ENA Browser Tools

This directory contains Docker images for ENA Browser Tools, a set of command-line utilities for downloading sequence data from the European Nucleotide Archive (ENA).

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/ena-tools/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/ena-tools/CVEs_latest.md) )
- `1.7.2` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/ena-tools/Dockerfile_1.7.2) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/ena-tools/CVEs_1.7.2.md) )

## Image Details

These Docker images are built from Python 3.12-slim and include:

- **enaDataGet**: Downloads data for individual sequence, assembly, read, or analysis accessions, or WGS sets
- **enaGroupGet**: Retrieves all data of a specific group (sequence, WGS, assembly, read, or analysis) for study/sample accessions or NCBI tax IDs
- Python 3.12 runtime
- CA certificates for HTTPS connections

The images are designed to be minimal and focused on the ENA Browser Tools with their essential dependencies.

## Citation

If you use ENA Browser Tools in your research, please cite the European Nucleotide Archive:

```
European Nucleotide Archive (ENA). EMBL-EBI. https://www.ebi.ac.uk/ena/browser/
```

**Tool homepage:** https://github.com/enasequence/enaBrowserTools

**ENA website:** https://www.ebi.ac.uk/ena/browser/

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/ena-tools:latest

# Or pull a specific version
docker pull getwilds/ena-tools:1.7.2

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/ena-tools:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/ena-tools:latest

# Or pull a specific version
apptainer pull docker://getwilds/ena-tools:1.7.2

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/ena-tools:latest
```

### Example Commands

#### Using enaDataGet

```bash
# Download a read file in FASTQ format
docker run --rm -v $(pwd):/data getwilds/ena-tools:latest \
  enaDataGet -f fastq -d /data ERR000001

# Download an assembly in FASTA format
docker run --rm -v $(pwd):/data getwilds/ena-tools:latest \
  enaDataGet -f fasta -d /data GCA_000001405.15

# Download sequence data in EMBL format
docker run --rm -v $(pwd):/data getwilds/ena-tools:latest \
  enaDataGet -f embl -d /data AM270342

# Using Apptainer
apptainer run --bind $(pwd):/data docker://getwilds/ena-tools:latest \
  enaDataGet -f fastq -d /data SRR000001
```

#### Using enaGroupGet

```bash
# Download all read files for a study in FASTQ format
docker run --rm -v $(pwd):/data getwilds/ena-tools:latest \
  enaGroupGet -g read -f fastq -d /data PRJNA123456

# Download all assemblies for a sample
docker run --rm -v $(pwd):/data getwilds/ena-tools:latest \
  enaGroupGet -g assembly -f fasta -d /data SAMN00000001

# Download all sequences for a taxonomic ID
docker run --rm -v $(pwd):/data getwilds/ena-tools:latest \
  enaGroupGet -g sequence -f embl -d /data 9606

# Using Apptainer
apptainer run --bind $(pwd):/data docker://getwilds/ena-tools:latest \
  enaGroupGet -g read -f fastq -d /data PRJEB12345
```

#### Common Options

```bash
# View help for enaDataGet
docker run --rm getwilds/ena-tools:latest enaDataGet --help

# View help for enaGroupGet
docker run --rm getwilds/ena-tools:latest enaGroupGet --help

# Download with Aspera (requires aspera_settings.ini configuration)
docker run --rm -v $(pwd):/data \
  -v /path/to/aspera_settings.ini:/aspera_settings.ini \
  getwilds/ena-tools:latest \
  enaDataGet -f fastq -as /aspera_settings.ini -d /data ERR000001
```

## Important Notes

### Supported Data Types

- **Sequences**: Can be downloaded in EMBL or FASTA format
- **Assemblies**: Can be downloaded in EMBL or FASTA format
- **Reads**: Can be downloaded in submitted, FASTQ, or SRA format
- **Analyses**: Can only be downloaded in submitted format

### Download Locations

By default, files are downloaded to the current directory. Use the `-d` flag to specify an output directory. When using Docker/Apptainer, make sure to mount your desired output location.

### Aspera Downloads

For faster downloads using Aspera, you'll need to:
1. Install Aspera Connect on your system
2. Create an `aspera_settings.ini` file with your Aspera configuration
3. Mount the configuration file into the container
4. Use the `-as` flag to specify the path to the configuration file

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Python 3.12-slim as the base image
2. Adds metadata labels for documentation and attribution
3. Installs wget and CA certificates with pinned versions
4. Downloads ENA Browser Tools v1.7.2 from GitHub
5. Copies the Python scripts to `/usr/local/bin` and makes them executable
6. Performs cleanup to minimize image size
7. Verifies both tools are functional via help commands

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/ena-tools), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
