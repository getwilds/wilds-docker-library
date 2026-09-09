# VRS-Python

This directory contains Docker images for VRS-Python, the GA4GH reference implementation of the Variation Representation Specification (VRS). It provides Python models, computed identifier generation, allele normalization, format translation (HGVS, SPDI, gnomAD-style), and VCF annotation for representing genetic variation in a standardized, machine-readable way.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/vrs-python/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/vrs-python/CVEs_latest.md) )
- `2.3.3` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/vrs-python/Dockerfile_2.3.3) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/vrs-python/CVEs_2.3.3.md) )

## Image Details

These Docker images are built from `python:3.12-slim` and include:

- VRS-Python (`ga4gh.vrs`) v2.3.3: GA4GH VRS models, computed identifiers, allele normalization, and the `vrs-annotate` command-line tool
- `[extras]` dependency group: `biocommons.seqrepo`, `hgvs`, `pysam`, `psycopg2-binary`, and `dill`, enabling the `ga4gh.vrs.extras` translator and VCF annotator
- `seqrepo` command-line tool: bundled via `biocommons.seqrepo`, used to download and manage the SeqRepo reference data that VRS-Python needs for normalization and translation
- `rsync`: required by the `seqrepo` CLI to pull reference data from the biocommons mirror
- System libraries (`libpq`, `zlib`, `bzip2`, `lzma`, `libcurl`): required to build and run `psycopg2` and `pysam`

The images are designed to be minimal and focused on VRS-Python with its essential dependencies.

### Reference data

VRS-Python needs a sequence data source for normalization and translation. Reference data is **not** bundled in the image (the full SeqRepo dataset is several GB and is versioned by release date). Provide one of the following at runtime:

- A local [SeqRepo](https://github.com/biocommons/biocommons.seqrepo) data directory, populated with the bundled `seqrepo` CLI (see below) and mounted into the container
- A [SeqRepo REST service](https://github.com/biocommons/seqrepo-rest-service) reachable over the network (`SEQREPO_REST_SERVICE_URL`)

The image sets `SEQREPO_ROOT_DIR=/usr/local/share/seqrepo` as the default location the `seqrepo` CLI and the VRS data proxy look for a data directory.

#### Downloading SeqRepo data

Populate a directory on the host once, then reuse it read-only for all subsequent runs:

```bash
# List the available dated instances
docker run --rm getwilds/vrs-python:latest seqrepo list-remote-instances

# Download an instance into a host directory (this transfers several GB)
docker run --rm -v /path/to/seqrepo:/usr/local/share/seqrepo \
  getwilds/vrs-python:latest \
  seqrepo pull -i 2024-02-20

# Verify the local copy
docker run --rm -v /path/to/seqrepo:/usr/local/share/seqrepo \
  getwilds/vrs-python:latest \
  seqrepo list-local-instances
```

Mount the same directory read-only when running `vrs-annotate` or the translator (see the examples below).

## Citation

If you use VRS-Python in your research, please cite the original authors:

```
Wagner AH, Babb L, Alterovitz G, et al. (2021). The GA4GH Variation Representation
Specification: A computational framework for variation representation and federated
identification. Cell Genomics, 1(2), 100027.
https://doi.org/10.1016/j.xgen.2021.100027
```

VRS-Python software (Zenodo): https://doi.org/10.5281/zenodo.14013256

**Tool homepage:** https://github.com/ga4gh/vrs-python

**Specification:** https://vrs.ga4gh.org/

Note: This Docker image is simply a containerized version of the tool. All credit for the tool's development goes to the original authors.

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/vrs-python:latest

# Or pull a specific version
docker pull getwilds/vrs-python:2.3.3

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/vrs-python:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/vrs-python:latest

# Or pull a specific version
apptainer pull docker://getwilds/vrs-python:2.3.3

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/vrs-python:latest
```

### Example Commands

```bash
# Example 1: Print the installed VRS-Python version
docker run --rm getwilds/vrs-python:latest \
  python -c "import ga4gh.vrs; print(ga4gh.vrs.__version__)"

# Example 2: Show help for the VCF annotation CLI
docker run --rm getwilds/vrs-python:latest vrs-annotate vcf --help

# Example 3: Download SeqRepo reference data into a host directory (one-time, several GB)
docker run --rm -v /path/to/seqrepo:/usr/local/share/seqrepo \
  getwilds/vrs-python:latest \
  seqrepo pull -i 2024-02-20

# Example 4: Annotate a VCF with VRS identifiers using the local SeqRepo directory
docker run --rm \
  -v /path/to/data:/data \
  -v /path/to/seqrepo:/usr/local/share/seqrepo:ro \
  getwilds/vrs-python:latest \
  vrs-annotate vcf --vcf-out /data/annotated.vcf.gz /data/input.vcf.gz

# Example 5: Translate an HGVS expression to a VRS Allele against a SeqRepo REST service
docker run --rm \
  -e SEQREPO_REST_SERVICE_URL=http://seqrepo-rest:5000/seqrepo \
  getwilds/vrs-python:latest \
  python -c "
from ga4gh.vrs.dataproxy import create_dataproxy
from ga4gh.vrs.extras.translator import AlleleTranslator
dp = create_dataproxy('seqrepo+http://seqrepo-rest:5000/seqrepo')
tr = AlleleTranslator(data_proxy=dp)
print(tr.translate_from('NC_000013.11:g.32936732G>C', 'hgvs').model_dump(exclude_none=True))
"

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/vrs-python:latest \
  vrs-annotate vcf --vcf-out /data/annotated.vcf.gz /data/input.vcf.gz

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data vrs-python_latest.sif \
  vrs-annotate vcf --vcf-out /data/annotated.vcf.gz /data/input.vcf.gz
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `python:3.12-slim` as the base image
2. Adds metadata labels for documentation and attribution
3. Configures the shell with `pipefail` for better error handling
4. Installs system build/runtime libraries with pinned versions (`libpq-dev`, `zlib1g-dev`, `libbz2-dev`, `liblzma-dev`, `libcurl4-openssl-dev`, `gcc`, `rsync`)
5. Installs `ga4gh.vrs[extras]` at the pinned version via pip with `--no-cache-dir`
6. Sets `SEQREPO_ROOT_DIR` to a default in-container path for the `seqrepo` CLI and the VRS data proxy
7. Runs a smoke test that imports the core modules and invokes `vrs-annotate --help`, `seqrepo --version`, and `rsync --version`

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/vrs-python), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
