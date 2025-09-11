# Delly

This directory contains Docker images for Delly, an integrated structural variant prediction method that can discover, genotype and visualize deletions, tandem duplications, inversions and translocations at single-nucleotide resolution in short-read and long-read massively parallel sequencing data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/delly/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/delly/CVEs_latest.md) )
- `1.2.9` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/delly/Dockerfile_1.2.9) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/delly/CVEs_1.2.9.md) )

## Image Details

These Docker images are built from Ubuntu 22.04 and include a statically compiled Delly binary with bcftools for BCF indexing and manipulation. The images use a multi-stage build process to minimize the final image size while ensuring all necessary dependencies are included. Delly uses paired-ends, split-reads and read-depth to sensitively and accurately delineate genomic rearrangements throughout the genome.

## Usage

### Docker

```bash
docker pull getwilds/delly:latest
# or
docker pull getwilds/delly:1.2.9

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/delly:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/delly:latest
# or
apptainer pull docker://getwilds/delly:1.2.9

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/delly:latest
```

### Example Commands

#### Basic Germline SV Discovery

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/delly:latest call \
  -g /data/reference.fasta \
  -o /data/sample.bcf \
  /data/sample.bam

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/delly:latest call \
  -g /data/reference.fasta \
  -o /data/sample.bcf \
  /data/sample.bam
```

#### Somatic SV Discovery (Tumor/Normal)

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/delly:latest call \
  -x /data/human.hg19.excl.tsv \
  -o /data/tumor_normal.bcf \
  -g /data/reference.fasta \
  /data/tumor.bam /data/normal.bam

# Filter for somatic variants
docker run --rm -v /path/to/data:/data getwilds/delly:latest filter \
  -f somatic \
  -o /data/somatic.bcf \
  -s /data/samples.tsv \
  /data/tumor_normal.bcf
```

#### Copy Number Variant (CNV) Calling

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/delly:latest cnv \
  -g /data/reference.fasta \
  -m /data/mappability.map \
  -o /data/sample.cnv.bcf \
  /data/sample.bam
```

#### Genotyping Known SV Sites

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/delly:latest call \
  -g /data/reference.fasta \
  -v /data/sites.bcf \
  -o /data/genotyped.bcf \
  /data/sample.bam
```

## Key Features

### **Structural Variant Types**
- **Deletions**: Large deletions detected via paired-end and split-read signatures
- **Duplications**: Tandem duplications identified through read-depth and paired-end analysis
- **Inversions**: Chromosomal inversions discovered using paired-end orientation patterns
- **Translocations**: Inter-chromosomal rearrangements detected via discordant paired-ends
- **Insertions**: Large insertions found through split-read analysis

### **Analysis Modes**
- **Germline mode**: Standard mode for detecting inherited structural variants
- **Somatic mode**: Specialized tumor/normal comparison for cancer analysis
- **CNV calling**: Copy number variant detection using read-depth analysis
- **Genotyping mode**: Re-genotype known SV sites in new samples

### **Input Requirements**
- **Coordinate-sorted BAM files** with associated index files (.bai)
- **Reference genome** in FASTA format with associated index (.fai)
- **Exclude regions** (optional): BED file of regions to exclude from analysis
- **Mappability map** (optional): For improved CNV calling accuracy

### **Output Formats**
- **BCF/VCF files**: Standard variant call format with comprehensive annotation
- **Structural variant coordinates**: Precise breakpoint locations when possible
- **Genotype information**: Quality scores and supporting read counts
- **Somatic filtering**: Specialized output for cancer genomics workflows

## Important Notes

### **System Requirements**
- Delly requires sorted, indexed, and duplicate-marked BAM files
- An indexed reference genome is required for split-read identification
- For optimal performance, use OMP_NUM_THREADS environment variable to control parallelization

### **Parallelization**
- Delly primarily parallelizes on the sample level
- Set OMP_NUM_THREADS to be less than or equal to the number of input samples
- Multi-threading is particularly effective for large cohort analyses

### **Size Limitations**
- For short-reads with insert size 200-300bp: reliable SV detection ≥300bp
- Small InDel calling using soft-clipped reads: minimum size 15bp
- For long-reads: SV detection ≥30bp

### **Quality Control**
- Evaluate mapping quality, duplicate rates, and insert size distributions before analysis
- Use exclude region files to mask repetitive or problematic genomic regions
- Consider mappability maps for improved accuracy in CNV calling

## Security Notice

**Important**: These Docker images are provided for research and educational purposes. Please be aware of the security implications when using these images in production environments.

However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/delly), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 22.04 as the base image for maximum compatibility
2. Adds metadata labels for documentation and attribution following WILDS standards
3. Installs all necessary build dependencies with pinned versions for reproducibility
4. Clones the Delly repository and compiles a static binary
5. Uses multi-stage build to create a minimal runtime image
6. Copies only the necessary binary to reduce final image size

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

## References

Tobias Rausch, Thomas Zichner, Andreas Schlattl, Adrian M. Stuetz, Vladimir Benes, Jan O. Korbel. DELLY: structural variant discovery by integrated paired-end and split-read analysis. Bioinformatics. 2012 Sep 15;28(18):i333-i339. https://doi.org/10.1093/bioinformatics/bts378
