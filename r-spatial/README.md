# r-spatial

This directory contains Docker images for r-spatial, an R environment for geospatial analysis built on Rocker/geospatial with additional commonly used spatial and utility CRAN packages.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/r-spatial/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/r-spatial/CVEs_latest.md) )
- `0.1.0` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/r-spatial/Dockerfile_0.1.0) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/r-spatial/CVEs_0.1.0.md) )

## Platform Availability

Both `linux/amd64` and `linux/arm64` are intended; `rocker/geospatial` publishes both architectures. ARM64 has not yet been verified for this image.

## Image Details

These Docker images are built from the `rocker/geospatial:4.6.1` base image (R 4.6.1) and include:

- Base image packages: `sf`, `terra`, `raster`, `stars`, `lwgeom`, the tidyverse, and the system libraries GDAL, GEOS, PROJ, and udunits
- gstat, spdep, data.table, lubridate: Also provided by the base image
- exactextractr: Fast and accurate raster-by-polygon summary statistics
- ggspatial: Map decorations (scale bars, north arrows, basemaps) for ggplot2
- rnaturalearth: Natural Earth basemap data
- tigris: US Census TIGER/Line boundary shapefiles
- optparse: Command-line argument parsing in R scripts

The added CRAN packages (exactextractr, ggspatial, rnaturalearth, tigris, optparse) are installed from a dated Posit Package Manager snapshot (2026-10-23); everything else is fixed by the `rocker/geospatial:4.6.1` base image tag. The exact package and GDAL/GEOS/PROJ versions are printed in the image build log by the smoke test.

Official documentation: [sf](https://r-spatial.github.io/sf/), [terra](https://rspatial.github.io/terra/), [Rocker project](https://rocker-project.org/images/versioned/rstudio.html#geospatial).

## Usage

### Docker

```bash
docker pull getwilds/r-spatial:latest
# or
docker pull getwilds/r-spatial:0.1.0

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/r-spatial:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/r-spatial:latest
# or
apptainer pull docker://getwilds/r-spatial:0.1.0

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/r-spatial:latest
```

### Example Commands

```bash
# Run an R script with Docker
docker run --rm -v /path/to/data:/data getwilds/r-spatial:latest \
  Rscript /data/analysis.R --input /data/regions.gpkg --output /data/results.csv

# Print GDAL/GEOS/PROJ versions
docker run --rm getwilds/r-spatial:latest \
  Rscript -e 'print(sf::sf_extSoftVersion())'

# Run an R script with Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/r-spatial:latest \
  Rscript /data/analysis.R --input /data/regions.gpkg --output /data/results.csv

# Apptainer (local SIF file)
apptainer run --bind /path/to/data:/data r-spatial_latest.sif \
  Rscript /data/analysis.R --input /data/regions.gpkg --output /data/results.csv
```

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/r-spatial), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses `rocker/geospatial:4.6.1` as the base image, which provides R, sf, terra, and the geospatial system libraries
2. Adds metadata labels for documentation and attribution
3. Sets bash with pipefail as the build shell
4. Sets R library paths to avoid host contamination in Apptainer
5. Installs additional R packages, failing the build if any is missing, and cleans up temporary files
6. Sets up a working directory for data analysis
7. Runs a smoke test that loads each package and prints versions

## Contributing

Issues and pull requests are welcome in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository. See the [contributing guidelines](https://github.com/getwilds/wilds-docker-library/blob/main/CONTRIBUTING.md).

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
