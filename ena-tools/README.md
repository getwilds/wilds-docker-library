# ENA FTP Downloader

This directory contains Docker images for ENA FTP Downloader, a Java-based tool for bulk downloading sequencing data from the European Nucleotide Archive (ENA) via FTP or Aspera.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/ena-tools/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/ena-tools/CVEs_latest.md) )
- `2.1.1` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/ena-tools/Dockerfile_2.1.1) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/ena-tools/CVEs_2.1.1.md) )

## Image Details

These Docker images are built from Eclipse Temurin JRE 21 (Alpine) and include:

- **ENA FTP Downloader**: Bulk download tool for ENA sequencing data
- Support for multiple data formats: READS_FASTQ, READS_SUBMITTED, READS_BAM, ANALYSIS_SUBMITTED, ANALYSIS_GENERATED
- FTP and Aspera protocol support
- Resilient and idempotent file retrieval
- Java 21 runtime environment

The images are designed to be minimal and focused on reliable FTP-based downloads from the European Nucleotide Archive.

## Citation

If you use ENA FTP Downloader in your research, please cite the European Nucleotide Archive:

```
European Nucleotide Archive (ENA). EMBL-EBI. https://www.ebi.ac.uk/ena/browser/
```

**Tool homepage:** https://github.com/enasequence/ena-ftp-downloader

**ENA website:** https://www.ebi.ac.uk/ena/browser/

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/ena-tools:latest

# Or pull a specific version
docker pull getwilds/ena-tools:2.1.1

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/ena-tools:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/ena-tools:latest

# Or pull a specific version
apptainer pull docker://getwilds/ena-tools:2.1.1

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/ena-tools:latest
```

### Example Commands

#### Interactive Mode

The tool can run in interactive mode, prompting you for parameters:

```bash
# Run in interactive mode
docker run --rm -it -v $(pwd):/data getwilds/ena-tools:latest ena-downloader

# Using Apptainer
apptainer run --bind $(pwd):/data docker://getwilds/ena-tools:latest ena-downloader
```

#### Download with Accession List

```bash
# Create a file with accession numbers (one per line)
echo "ERR000001" > accessions.txt
echo "ERR000002" >> accessions.txt

# Download FASTQ files for all accessions
docker run --rm -v $(pwd):/data getwilds/ena-tools:latest \
  ena-downloader \
  --accessions /data/accessions.txt \
  --format READS_FASTQ \
  --location /data \
  --protocol FTP

# Using Apptainer
apptainer run --bind $(pwd):/data docker://getwilds/ena-tools:latest \
  ena-downloader \
  --accessions /data/accessions.txt \
  --format READS_FASTQ \
  --location /data \
  --protocol FTP
```

#### Download with Search Query

```bash
# Download using a query
docker run --rm -v $(pwd):/data getwilds/ena-tools:latest \
  ena-downloader \
  --query "study_accession=PRJNA123456" \
  --format READS_FASTQ \
  --location /data \
  --protocol FTP
```

#### Download BAM Files

```bash
# Download BAM format
docker run --rm -v $(pwd):/data getwilds/ena-tools:latest \
  ena-downloader \
  --accessions /data/accessions.txt \
  --format READS_BAM \
  --location /data \
  --protocol FTP
```

#### Using Aspera for Faster Downloads

```bash
# Download using Aspera protocol (requires Aspera configuration)
docker run --rm -v $(pwd):/data getwilds/ena-tools:latest \
  ena-downloader \
  --accessions /data/accessions.txt \
  --format READS_FASTQ \
  --location /data \
  --protocol ASPERA \
  --aspera-location /path/to/aspera
```

#### View Help

```bash
# View help information
docker run --rm getwilds/ena-tools:latest ena-downloader --help
```

## Important Notes

### Supported Data Formats

- **READS_FASTQ**: Read files in FASTQ format
- **READS_SUBMITTED**: Reads in originally submitted format
- **READS_BAM**: Read files in BAM format
- **ANALYSIS_SUBMITTED**: Analysis files in originally submitted format
- **ANALYSIS_GENERATED**: Generated analysis files

### Download Protocols

- **FTP**: Standard FTP protocol (default, no additional setup required)
- **ASPERA**: High-speed Aspera protocol (requires Aspera Connect installation and configuration)

### Authentication for Restricted Data

If you need to download restricted data, you can provide data hub credentials:

```bash
docker run --rm -v $(pwd):/data getwilds/ena-tools:latest \
  ena-downloader \
  --accessions /data/accessions.txt \
  --format READS_FASTQ \
  --location /data \
  --protocol FTP \
  --username your_username \
  --password your_password \
  --hub-name your_hub_name
```

### Resilient Downloads

The tool is designed to be idempotent and resilient - it can be safely re-run and will skip already downloaded files, making it ideal for interrupted downloads or large batch operations.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Eclipse Temurin JRE 21 Alpine as the base image for minimal size
2. Adds metadata labels for documentation and attribution
3. Installs wget and unzip with pinned versions
4. Downloads the ENA FTP Downloader ZIP from the official ENA FTP site
5. Extracts and installs the JAR file to `/usr/local/bin`
6. Creates a convenient wrapper script (`ena-downloader`) for easier execution
7. Performs cleanup to minimize image size
8. Verifies the tool is functional via help command

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/ena-tools), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
