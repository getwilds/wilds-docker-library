# Mosdepth

This directory contains Docker images for [mosdepth](https://github.com/brentp/mosdepth), a fast tool for calculating sequencing coverage depth from BAM or CRAM alignments at per-base, per-region, or per-window resolution.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/mosdepth/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/mosdepth/CVEs_latest.md) )
- `0.3.14` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/mosdepth/Dockerfile_0.3.14) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/mosdepth/CVEs_0.3.14.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- mosdepth v0.3.14: A fast BAM/CRAM coverage calculator that produces per-base, per-region, or windowed depth output in BED-compatible formats.
- htslib runtime dependencies (`libcurl4`, `zlib1g`, `libbz2-1.0`, `liblzma5`): required by the statically linked mosdepth binary for compressed and remote file I/O.

The image installs the official pre-built Linux x86_64 binary from the upstream GitHub release, keeping the image small and focused on a single primary tool.

> **Platform note:** The upstream project only distributes an x86_64 binary, so these images are built for `linux/amd64` only. ARM64 builds are skipped via `amd64_only_tools.txt`.

## Citation

If you use mosdepth in your research, please cite the original authors:

```
Pedersen BS, Quinlan AR. Mosdepth: quick coverage calculation for genomes and
exomes. Bioinformatics. 2018 Mar 1;34(5):867-868.
doi:10.1093/bioinformatics/btx699
```

**Tool homepage:** https://github.com/brentp/mosdepth

**Publication:** https://doi.org/10.1093/bioinformatics/btx699

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/mosdepth:latest

# Or pull a specific version
docker pull getwilds/mosdepth:0.3.14

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/mosdepth:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/mosdepth:latest

# Or pull a specific version
apptainer pull docker://getwilds/mosdepth:0.3.14

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/mosdepth:latest
```

### Example Commands

```bash
# Per-base coverage across the whole genome
docker run --rm -v /path/to/data:/data getwilds/mosdepth:latest \
  mosdepth /data/sample sample.bam

# Per-region coverage using a BED of target intervals (e.g., exome capture)
docker run --rm -v /path/to/data:/data getwilds/mosdepth:latest \
  mosdepth --by /data/targets.bed /data/sample_exome /data/sample.bam

# Fixed-size 500 bp windows with no per-base output, using 4 threads
docker run --rm -v /path/to/data:/data getwilds/mosdepth:latest \
  mosdepth --no-per-base --by 500 --threads 4 /data/sample_windows /data/sample.bam

# CRAM input requires a reference FASTA
docker run --rm -v /path/to/data:/data getwilds/mosdepth:latest \
  mosdepth --fasta /data/reference.fa /data/sample_cram /data/sample.cram

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/mosdepth:latest \
  mosdepth --by /data/targets.bed /data/sample_exome /data/sample.bam

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data mosdepth_latest.sif \
  mosdepth /data/sample /data/sample.bam
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Dynamically determines and pins the latest security-patched versions of the runtime dependencies mosdepth needs (htslib's compression and HTTPS libraries)
4. Downloads the official pre-built `mosdepth` binary from the upstream GitHub release and installs it to `/usr/local/bin`
5. Sets `/data` as the default working directory for analyses
6. Runs `mosdepth --version` as a smoke test to verify the install

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/mosdepth), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
