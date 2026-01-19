# GLIMPSE2

This directory contains Docker images for GLIMPSE2, a set of tools for low-coverage whole genome sequencing imputation designed specifically for reference panels with hundreds of thousands of samples, emphasizing rare variant detection.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/glimpse2/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/glimpse2/CVEs_latest.md) )
- `2.0.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/glimpse2/Dockerfile_2.0.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/glimpse2/CVEs_2.0.0.md) )

## Image Details

These Docker images are built from Ubuntu 22.04 and include:

- GLIMPSE2 v2.0.0: Low-coverage whole genome sequencing imputation toolkit
- HTSlib 1.16: High-throughput sequencing data library
- bcftools 1.16: Utilities for variant calling and manipulating VCFs and BCFs
- Boost 1.78.0: C++ libraries (iostreams, program_options, serialization)

The images include five main GLIMPSE2 tools:

| Tool | Description |
|------|-------------|
| `GLIMPSE2_chunk` | Defines chunks for imputation |
| `GLIMPSE2_split_reference` | Prepares the reference panel |
| `GLIMPSE2_phase` | Performs imputation and phasing |
| `GLIMPSE2_ligate` | Ligates multiple phased chunks into chromosomes |
| `GLIMPSE2_concordance` | Computes imputation accuracy metrics |

The images are designed to be minimal and focused on GLIMPSE2 with its essential runtime dependencies. Build-time dependencies are removed after compilation to reduce the final image size.

## Citation

If you use GLIMPSE2 in your research, please cite the original authors:

```
Rubinacci S, Ribeiro DM, Hofmeister RJ, Delaneau O.
Efficient phasing and imputation of low-coverage sequencing data using large reference panels.
Nature Genetics 53, 120-126 (2021).
https://doi.org/10.1038/s41588-020-00756-0
```

**Tool homepage:** https://github.com/odelaneau/GLIMPSE

**Documentation:** https://odelaneau.github.io/GLIMPSE/

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/glimpse2:latest

# Or pull a specific version
docker pull getwilds/glimpse2:2.0.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/glimpse2:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/glimpse2:latest

# Or pull a specific version
apptainer pull docker://getwilds/glimpse2:2.0.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/glimpse2:latest
```

### Example Commands

```bash
# Example 1: Define chunks for a chromosome
docker run --rm -v /path/to/data:/data getwilds/glimpse2:latest \
  GLIMPSE2_chunk \
  --input /data/reference_panel.vcf.gz \
  --region chr20 \
  --output /data/chunks.txt

# Example 2: Split the reference panel into binary format
docker run --rm -v /path/to/data:/data getwilds/glimpse2:latest \
  GLIMPSE2_split_reference \
  --reference /data/reference_panel.vcf.gz \
  --map /data/genetic_map.txt \
  --input-region chr20:1000000-2000000 \
  --output-region chr20:1000000-2000000 \
  --output /data/reference_chunk

# Example 3: Impute and phase low-coverage data
docker run --rm -v /path/to/data:/data getwilds/glimpse2:latest \
  GLIMPSE2_phase \
  --bam-file /data/sample.bam \
  --reference /data/reference_chunk.bin \
  --output /data/imputed_chunk.bcf

# Example 4: Ligate phased chunks into full chromosomes
docker run --rm -v /path/to/data:/data getwilds/glimpse2:latest \
  GLIMPSE2_ligate \
  --input /data/chunks_list.txt \
  --output /data/imputed_chr20.bcf

# Example 5: Compute imputation accuracy metrics
docker run --rm -v /path/to/data:/data getwilds/glimpse2:latest \
  GLIMPSE2_concordance \
  --input /data/imputed.vcf.gz \
  --truth /data/truth.vcf.gz \
  --output /data/concordance_report

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/glimpse2:latest \
  GLIMPSE2_phase \
  --bam-file /data/sample.bam \
  --reference /data/reference_chunk.bin \
  --output /data/imputed_chunk.bcf

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data glimpse2_latest.sif \
  GLIMPSE2_phase \
  --bam-file /data/sample.bam \
  --reference /data/reference_chunk.bin \
  --output /data/imputed_chunk.bcf
```

## Important Notes

### Architecture Support

**This image is AMD64 only.** GLIMPSE2 is compiled with AVX2 instructions (`-mavx2`) for optimal performance, which are only available on x86_64 processors (Intel Haswell and newer, AMD Excavator and newer). The image will not run on ARM64 systems.

### Typical Workflow

A typical GLIMPSE2 imputation workflow follows these steps:

1. **Chunk definition** (`GLIMPSE2_chunk`): Define genomic chunks for parallel processing
2. **Reference preparation** (`GLIMPSE2_split_reference`): Convert reference panel to binary format
3. **Imputation** (`GLIMPSE2_phase`): Impute and phase each chunk
4. **Ligation** (`GLIMPSE2_ligate`): Combine chunks into full chromosomes
5. **Validation** (`GLIMPSE2_concordance`): Assess imputation quality (optional)

### Memory Requirements

GLIMPSE2 is optimized for large reference panels. Memory requirements depend on:
- Reference panel size (number of samples and variants)
- Chunk size
- Number of threads

For large reference panels (e.g., TOPMed, UK Biobank), ensure adequate memory is available.

### Thread Usage

Most GLIMPSE2 tools support multi-threading via the `--threads` flag:

```bash
docker run --rm -v /path/to/data:/data getwilds/glimpse2:latest \
  GLIMPSE2_phase \
  --threads 8 \
  --bam-file /data/sample.bam \
  --reference /data/reference_chunk.bin \
  --output /data/imputed_chunk.bcf
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 22.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Installs system dependencies with pinned versions for reproducibility
4. Downloads and compiles Boost 1.78.0 (iostreams, program_options, serialization)
5. Downloads and compiles HTSlib 1.16 (minimal configuration)
6. Downloads and compiles bcftools 1.16
7. Clones and compiles GLIMPSE2 v2.0.0 from source
8. Cleans up build artifacts
9. Sets working directory to /data
10. Performs a smoke test to verify all tools are functional

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/glimpse2), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
