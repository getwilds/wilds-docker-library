# python-utils

This directory contains Docker images for python-utils, a lean general-purpose Python environment that bundles a handful of ubiquitous scientific computing and bioinformatics packages on top of a slim Python base.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/python-utils/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/python-utils/CVEs_latest.md) )
- `0.1.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/python-utils/Dockerfile_0.1.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/python-utils/CVEs_0.1.0.md) )

## Image Details

These Docker images are built from the `python:3.12-slim` base image and include:

- git: version control client, included to support WDL workflows that clone repositories at runtime
- pysam 0.23.3: Python interface to htslib for reading/writing SAM/BAM/VCF/BCF files
- numpy 2.4.4: Core N-dimensional array library for numerical computing
- scipy 1.17.1: Scientific computing library (optimization, stats, signal processing, etc.)
- pandas 3.0.2: Data frames and tabular data analysis
- matplotlib 3.10.9: Plotting and visualization library
- seaborn 0.13.2: Statistical data visualization built on matplotlib

The images are designed to be a lean, general-purpose Python environment for WILDS WDL modules and analyses that need common scientific/bioinformatics packages without the heavy footprint of deep learning frameworks. For GPU-accelerated deep learning workflows, see the `python-dl` image instead.

## Citation

This image simply bundles several widely used open-source Python packages. If you use them in your research, please cite the original authors:

- **pysam**: https://github.com/pysam-developers/pysam (wraps htslib — Bonfield et al., *GigaScience* 2021, https://doi.org/10.1093/gigascience/giab007)
- **NumPy**: Harris, C.R., et al. (2020). Array programming with NumPy. *Nature* 585, 357–362. https://doi.org/10.1038/s41586-020-2649-2
- **SciPy**: Virtanen, P., et al. (2020). SciPy 1.0: fundamental algorithms for scientific computing in Python. *Nature Methods* 17, 261–272. https://doi.org/10.1038/s41592-019-0686-2
- **pandas**: McKinney, W. (2010). Data Structures for Statistical Computing in Python. *Proc. 9th Python in Science Conference*. https://doi.org/10.25080/Majora-92bf1922-00a
- **Matplotlib**: Hunter, J. D. (2007). Matplotlib: A 2D Graphics Environment. *Computing in Science & Engineering* 9(3), 90–95. https://doi.org/10.1109/MCSE.2007.55
- **seaborn**: Waskom, M. L. (2021). seaborn: statistical data visualization. *Journal of Open Source Software* 6(60), 3021. https://doi.org/10.21105/joss.03021

## Usage

### Docker

```bash
docker pull getwilds/python-utils:latest
# or
docker pull getwilds/python-utils:0.1.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/python-utils:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/python-utils:latest
# or
apptainer pull docker://getwilds/python-utils:0.1.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/python-utils:latest
```

### Example Commands

```bash
# Run a Python analysis script with Docker
docker run --rm -v /path/to/data:/data getwilds/python-utils:latest \
  python /data/analysis.py --input /data/input.csv --output /data/results.csv

# Drop into an interactive Python shell
docker run --rm -it -v /path/to/data:/data getwilds/python-utils:latest python

# Inspect a BAM file with pysam
docker run --rm -v /path/to/data:/data getwilds/python-utils:latest \
  python -c "import pysam; bam = pysam.AlignmentFile('/data/sample.bam', 'rb'); print(bam.header)"

# Run a Python script with Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/python-utils:latest \
  python /data/analysis.py --input /data/input.csv --output /data/results.csv

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data python-utils_latest.sif \
  python /data/analysis.py --input /data/input.csv --output /data/results.csv
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `python:3.12-slim` as the base image for a minimal Python environment
2. Adds metadata labels for documentation and attribution
3. Sets the shell pipefail option for safer pipelines
4. Installs git via apt with the candidate version captured from `apt-cache policy`, then cleans up `/var/lib/apt/lists`
5. Installs the scientific/bioinformatics Python packages via pip with pinned versions and `--no-cache-dir`
6. Sets `/data` as the working directory for analysis
7. Runs a smoke test that imports each package and prints its version

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/python-utils), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
