# BEDOPS

This directory contains Docker images for BEDOPS, a high-performance genomic interval operations toolkit for working with BED files and other genomic data formats.

[Official Documentation](https://bedops.readthedocs.io/)

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bedops/Dockerfile_latest) | Vulnerability Report )
- `2.4.42` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/bedops/Dockerfile_2.4.42) | Vulnerability Report )

## Platform Availability

**AMD64-only**: This image is only available for `linux/amd64` architecture. The BEDOPS pre-built binaries are compiled specifically for x86_64 systems and are not available for ARM64.

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- **BEDOPS v2.4.42**: Complete suite of 80+ tools for genomic interval operations

BEDOPS is designed for fast operations on BED files and includes tools for file conversion, set operations, statistical analysis, and data manipulation.

## About BEDOPS

BEDOPS is a suite of tools to address common questions raised in genomic studies — mostly with regard to overlap and proximity relationships between data sets. It aims to be scalable and flexible, facilitating the efficient and accurate analysis and management of large-scale genomic data.

**Key Features:**
- Fast set operations (union, intersection, difference, complement)
- File format conversion (GTF, GFF, VCF, BAM, SAM, WIG to BED)
- Statistical operations on genomic intervals
- Efficient sorting and merging
- Element extraction and mapping

## Usage

### Docker

```bash
docker pull getwilds/bedops:latest
# or
docker pull getwilds/bedops:2.4.42

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/bedops:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/bedops:latest
# or
apptainer pull docker://getwilds/bedops:2.4.42

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/bedops:latest
```

### Example Commands

BEDOPS provides numerous tools for genomic analysis. Here are some common examples:

#### GTF to BED Conversion

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/bedops:latest \
  gtf2bed < /data/genes.gtf > /data/genes.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bedops:latest \
  gtf2bed < /data/genes.gtf > /data/genes.bed
```

#### GFF to BED Conversion

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/bedops:latest \
  gff2bed < /data/annotations.gff > /data/annotations.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bedops:latest \
  gff2bed < /data/annotations.gff > /data/annotations.bed
```

#### VCF to BED Conversion

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/bedops:latest \
  vcf2bed < /data/variants.vcf > /data/variants.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bedops:latest \
  vcf2bed < /data/variants.vcf > /data/variants.bed
```

#### Set Operations (Union, Intersection, Difference)

```bash
# Union of two BED files
docker run --rm -v /path/to/data:/data getwilds/bedops:latest \
  bedops --union /data/file1.bed /data/file2.bed > /data/union.bed

# Intersection
docker run --rm -v /path/to/data:/data getwilds/bedops:latest \
  bedops --intersect /data/file1.bed /data/file2.bed > /data/intersect.bed

# Difference (elements in file1 not in file2)
docker run --rm -v /path/to/data:/data getwilds/bedops:latest \
  bedops --difference /data/file1.bed /data/file2.bed > /data/diff.bed

# Complement
docker run --rm -v /path/to/data:/data getwilds/bedops:latest \
  bedops --complement /data/file.bed > /data/complement.bed
```

#### Mapping Operations with bedmap

```bash
# Count overlaps
docker run --rm -v /path/to/data:/data getwilds/bedops:latest \
  bedmap --count /data/regions.bed /data/features.bed > /data/overlap_counts.bed

# Calculate mean of scores
docker run --rm -v /path/to/data:/data getwilds/bedops:latest \
  bedmap --mean /data/regions.bed /data/scored_features.bed > /data/mean_scores.bed
```

#### Sorting BED Files

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/bedops:latest \
  sort-bed /data/unsorted.bed > /data/sorted.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bedops:latest \
  sort-bed /data/unsorted.bed > /data/sorted.bed
```

#### BAM to BED Conversion

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/bedops:latest \
  bam2bed < /data/alignments.bam > /data/alignments.bed

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/bedops:latest \
  bam2bed < /data/alignments.bam > /data/alignments.bed
```

### Available BEDOPS Tools

The image includes 80+ tools organized into several categories:

#### Core Set Operations
- `bedops` - Set operations on BED files (union, intersection, difference, complement, etc.)
- `bedmap` - Map genomic intervals and apply operations
- `bedextract` - Extract elements from BED files

#### File Conversion Tools
| Tool | Description |
|------|-------------|
| `gtf2bed` | Convert GTF to BED format |
| `gff2bed` | Convert GFF to BED format |
| `vcf2bed` | Convert VCF to BED format |
| `bam2bed` | Convert BAM to BED format |
| `sam2bed` | Convert SAM to BED format |
| `wig2bed` | Convert WIG to BED format |
| `psl2bed` | Convert PSL to BED format |
| `gvf2bed` | Convert GVF to BED format |
| `rmsk2bed` | Convert RepeatMasker output to BED format |
| `convert2bed` | General-purpose conversion utility |

#### Utility Tools
- `sort-bed` - Sort BED files efficiently
- `switch-BEDOPS-binary-type` - Switch between different BEDOPS build types
- `update-sort-bed-*` - Migration and update utilities

#### Python Helper Scripts
- `bed_bigwig_profile.py` - Profile BigWig data
- `bed_build_windows.py` - Build genomic windows
- `bed_complement.py` - Complement operations
- `bed_count_by_interval.py` - Count features by interval
- `bed_count_overlapping.py` - Count overlapping features
- `bed_coverage.py` - Calculate coverage
- `bed_coverage_by_interval.py` - Coverage by interval
- `bed_diff_basewise_summary.py` - Base-wise difference summary
- `bed_extend_to.py` - Extend elements
- `bed_intersect.py` - Intersection operations
- `bed_intersect_basewise.py` - Base-wise intersection
- `bed_merge_overlapping.py` - Merge overlapping elements
- `bed_rand_intersect.py` - Random intersection
- `bed_subtract_basewise.py` - Base-wise subtraction

For complete documentation of all tools and their options, see the [official BEDOPS documentation](https://bedops.readthedocs.io/).

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs wget with pinned version
4. Downloads and extracts BEDOPS v2.4.42 pre-built binaries
5. Copies binaries to `/usr/local/bin/`
6. Includes a smoke test to verify installation (`bedops --version`)

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/bedops), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

## Contributing

See the [CONTRIBUTING.md](../.github/CONTRIBUTING.md) for guidelines on how to contribute to this project.

## License

BEDOPS is distributed under the GNU General Public License v2. This Docker image is distributed under the MIT License. See the [LICENSE](../LICENSE) file for details.
