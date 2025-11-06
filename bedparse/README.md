# bedparse

This directory contains Docker images for bedparse, a Python module and CLI tool for performing operations on BED files.

[Official Documentation](https://bedparse.readthedocs.io/)

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bedparse/Dockerfile_latest) | Vulnerability Report )
- `0.2.3` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bedparse/Dockerfile_0.2.3) | Vulnerability Report )

## Image Details

These Docker images are built from the Python 3.12 slim image and include:

- **bedparse v0.2.3**: Python CLI tool for BED file operations including GTF to BED12 conversion

The images are designed to be minimal and focused on bedparse functionality.

## About bedparse

bedparse provides 11 sub-commands for common operations on BED files:
- GTF to BED12 format conversion
- Feature extraction (promoters, introns, coding sequences, UTRs)
- File filtering and joining capabilities
- Format conversions (UCSC to Ensembl chromosome naming)
- Format validation

**Key Features:**
- Converts GTF files to BED12 format with proper CDS annotation
- Supports extra GTF fields for custom annotations
- Handles both Ensembl and UCSC GTF formats
- Provides filtering options during conversion

## Usage

### Docker

```bash
docker pull getwilds/bedparse:latest
# or
docker pull getwilds/bedparse:0.2.3

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/bedparse:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/bedparse:latest
# or
apptainer pull docker://getwilds/bedparse:0.2.3

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/bedparse:latest
```

### Example Commands

#### GTF to BED12 Conversion

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/bedparse:latest \
  bedparse gtf2bed /data/genes.gtf > /data/genes.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bedparse:latest \
  bedparse gtf2bed /data/genes.gtf > /data/genes.bed
```

#### GTF to BED12 with Extra Fields

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/bedparse:latest \
  bedparse gtf2bed --extraFields gene_id,gene_name /data/genes.gtf > /data/genes.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bedparse:latest \
  bedparse gtf2bed --extraFields gene_id,gene_name /data/genes.gtf > /data/genes.bed
```

#### Extract 3' UTRs from BED12

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/bedparse:latest \
  bedparse 3pUTR /data/genes.bed > /data/3pUTRs.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bedparse:latest \
  bedparse 3pUTR /data/genes.bed > /data/3pUTRs.bed
```

#### Extract Promoter Regions

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/bedparse:latest \
  bedparse promoter --dist 1000 /data/genes.bed > /data/promoters.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bedparse:latest \
  bedparse promoter --dist 1000 /data/genes.bed > /data/promoters.bed
```

#### Convert Chromosome Naming (UCSC to Ensembl)

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/bedparse:latest \
  bedparse convertChr --target Ensembl /data/genes.bed > /data/genes_ensembl.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bedparse:latest \
  bedparse convertChr --target Ensembl /data/genes.bed > /data/genes_ensembl.bed
```

### Available bedparse Sub-commands

| Command | Description |
|---------|-------------|
| `gtf2bed` | Converts a GTF file to BED12 format |
| `bed12tobed6` | Converts a BED12 file to BED6 format |
| `3pUTR` | Prints the 3' UTR of coding genes |
| `5pUTR` | Prints the 5' UTR of coding genes |
| `cds` | Prints the CDS of coding genes |
| `promoter` | Prints the promoters of transcripts |
| `introns` | Prints BED records corresponding to the introns |
| `filter` | Filters a BED file based on an annotation |
| `join` | Joins a BED file with an annotation file |
| `convertChr` | Convert chromosome names between UCSC and Ensembl |
| `validateFormat` | Check whether the BED file adheres to specifications |

For detailed usage of each command, run:
```bash
docker run --rm getwilds/bedparse:latest bedparse <command> --help
```

## GTF to BED12 Conversion Details

The `gtf2bed` command specifically converts GTF files to BED12 format with the following features:

- **CDS Annotation**: If the GTF file annotates 'CDS', 'start_codon', or 'stop_codon', these are used to annotate the thickStart and thickEnd in the BED file
- **Transcript Features**: Supports Ensembl GTF format (uses 'transcript' features) with customizable feature names
- **Extra Fields**: Can include additional GTF fields (e.g., gene_id, gene_name) as extra columns after column 12
- **Filtering**: Can filter transcripts by specific GTF field values during conversion

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Python 3.12 slim as the base image
2. Adds metadata labels for documentation and attribution
3. Installs bedparse via pip with pinned version (0.2.3)
4. Uses `--no-cache-dir` to minimize image size
5. Includes a smoke test to verify installation

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/bedparse), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

## Contributing

See the [CONTRIBUTING.md](../.github/CONTRIBUTING.md) for guidelines on how to contribute to this project.

## License

bedparse is distributed under the MIT License. This Docker image is also distributed under the MIT License. See the [LICENSE](../LICENSE) file for details.
