# Manta

This directory contains Docker images for Manta, a structural variant caller designed for high-performance detection of large insertions, deletions, duplications, inversions, and translocations from sequencing data.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/manta/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/manta/CVEs_latest.md) )
- `1.6.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/manta/Dockerfile_1.6.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/manta/CVEs_1.6.0.md) )

## Image Details

These Docker images are built from Python 2.7 Slim and include Manta v1.6.0. The images are designed to be minimal and focused on structural variant detection with only the necessary dependencies.

## Usage

### Docker

```bash
docker pull getwilds/manta:latest
# or
docker pull getwilds/manta:1.6.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/manta:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/manta:latest
# or
apptainer pull docker://getwilds/manta:1.6.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/manta:latest
```

### Example Commands

#### Basic DNA-seq Analysis

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/manta:latest configManta.py \
  --bam /data/sample.bam \
  --referenceFasta /data/reference.fasta \
  --runDir /data/manta_analysis

docker run --rm -v /path/to/data:/data getwilds/manta:latest \
  /data/manta_analysis/runWorkflow.py -m local -j 8

# Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/manta:latest configManta.py \
  --bam /data/sample.bam \
  --referenceFasta /data/reference.fasta \
  --runDir /data/manta_analysis

apptainer run --bind /path/to/data:/data docker://getwilds/manta:latest \
  /data/manta_analysis/runWorkflow.py -m local -j 8
```

#### Targeted Analysis with BED file

```bash
# Docker
docker run --rm -v /path/to/data:/data getwilds/manta:latest configManta.py \
  --bam /data/sample.bam \
  --referenceFasta /data/reference.fasta \
  --callRegions /data/target_regions.bed.gz \
  --runDir /data/manta_targeted
```

## Key Features

### **Structural Variant Types**
- **Deletions**: Large deletions (>50bp typically)
- **Insertions**: Large insertions and mobile element insertions
- **Duplications**: Tandem duplications and dispersed duplications
- **Inversions**: Chromosomal inversions
- **Translocations**: Inter-chromosomal rearrangements

### **Analysis Modes**
- **DNA-seq mode**: Standard mode for whole genome and targeted sequencing
- **RNA-seq mode**: Specialized mode accounting for splicing events
- **Targeted mode**: Optimized analysis for specific genomic regions

### **Input Requirements**
- **Coordinate-sorted BAM files** with associated index files
- **Reference genome FASTA** with associated index (.fai)
- **Optional BED file** for targeted analysis (must be bgzip compressed and tabix indexed)

## Output Files

Manta generates several key output files:

- **diploidSV.vcf.gz**: Primary structural variant calls
- **candidateSV.vcf.gz**: All candidate structural variants before filtering
- **candidateSmallIndels.vcf.gz**: Small indel candidates
- **somaticSV.vcf.gz**: Somatic variants (tumor-normal mode only)

## Performance Considerations

### **Resource Requirements**
- **Memory**: 8-16GB recommended for whole genome analysis
- **CPU**: Scales well with multiple cores (8+ recommended)
- **Storage**: Requires temporary space (~2-3x input BAM size)

### **Optimization Tips**
- Use `--callRegions` for targeted sequencing to improve speed
- Consider splitting large genomes by chromosome for very large datasets
- Ensure input BAMs are properly sorted and indexed

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/manta), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
