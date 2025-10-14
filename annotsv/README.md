# AnnotSV

This directory contains Docker images for AnnotSV, a tool for annotating and ranking structural variants (SVs).

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/annotsv/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/annotsv/CVEs_latest.md) )
- `3.4.4` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/annotsv/Dockerfile_3.4.4) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/annotsv/CVEs_3.4.4.md) )

## Image Details

These Docker images are built from Ubuntu 22.04 base image and include:

- AnnotSV v3.4.4: A tool for annotating and ranking structural variants from VCF files
- Pre-installed human annotation databases for immediate use
- Essential runtime dependencies including bedtools, bcftools, tcl, and unzip
- Properly configured environment with AnnotSV in PATH

The images use a multi-stage build process to minimize final image size by separating build-time dependencies (gcc, make, wget) from runtime dependencies. This results in smaller, more efficient images focused solely on providing AnnotSV functionality for structural variant annotation workflows.

## Usage

### Docker

```bash
docker pull getwilds/annotsv:latest
# or
docker pull getwilds/annotsv:3.4.4

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/annotsv:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/annotsv:latest
# or
apptainer pull docker://getwilds/annotsv:3.4.4

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/annotsv:latest
```

### Example Commands

```bash
# Basic help and version information
docker run --rm getwilds/annotsv:latest AnnotSV -help

# Annotate structural variants from a VCF file
docker run --rm -v /path/to/data:/data getwilds/annotsv:latest \
  AnnotSV -SVinputFile /data/input.vcf -outputDir /data/output

# Specify genome build and minimum SV size
docker run --rm -v /path/to/data:/data getwilds/annotsv:latest \
  AnnotSV -SVinputFile /data/input.vcf -outputDir /data/output \
  -genomeBuild GRCh38 -SVminSize 50

# Run with Apptainer using local SIF file
apptainer exec annotsv_latest.sif AnnotSV -SVinputFile /data/input.vcf -outputDir /data/output

# Run with Apptainer from registry
apptainer run --bind /path/to/data:/data docker://getwilds/annotsv:latest \
  AnnotSV -SVinputFile /data/input.vcf -outputDir /data/output
```

### Common AnnotSV Options

- `-SVinputFile`: Input VCF file containing structural variants
- `-outputDir`: Directory for output files
- `-genomeBuild`: Genome build (GRCh37 or GRCh38)
- `-SVminSize`: Minimum SV size to consider (default: 50bp)
- `-includeCI`: Include confidence intervals in output
- `-annotationsDir`: Directory containing annotation databases (pre-configured in container)

### Environment Variables

The container includes these pre-configured environment variables:

- `ANNOTSV`: Points to the AnnotSV installation directory (`/AnnotSV-3.4.4`)
- `PATH`: Includes the AnnotSV binary directory, allowing direct execution of `AnnotSV` command

### Functionality Limitations

- Exomiser reference data has been deleted from the image as it is way too big and isn't used frequently within the WILDS WDL ecosystem.
- For use in Apptainer, we recommend sticking with the default promoter size of 500, as custom promoter sizes require writing to the container's file system (which frequently isn't allowed in Apptainer).

## Integration with WILDS

This container is designed for use in structural variant analysis workflows within the WILDS ecosystem. It complements existing variant annotation tools like Annovar for comprehensive genomic analysis, particularly useful for:

- Leukemia research workflows detecting translocations and large rearrangements
- Structural variant calling pipelines using tools like Manta
- Comprehensive genomic analysis combining SNV/indel and structural variant detection

## Security Features

The AnnotSV Docker images include:

- Multi-stage build to exclude build tools from final image
- Minimal Ubuntu base image with only essential runtime dependencies
- Version-pinned package installations for reproducibility
- SSL certificate support for secure downloads (build stage only)
- Cleaned package cache to minimize image size
- Secure download practices with verified checksums

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/tree/main/annotsv), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Dockerfile Structure

The Dockerfile uses a multi-stage build with the following structure:

**Builder Stage:**
1. Uses Ubuntu 22.04 as the base image for stability and security
2. Installs build-time dependencies (wget, make, gcc, ca-certificates)
3. Downloads and extracts AnnotSV v3.4.4 source code
4. Compiles and installs AnnotSV with human annotations
5. Removes Exomiser annotations to reduce image size

**Runtime Stage:**
1. Starts fresh from Ubuntu 22.04 base image
2. Adds metadata labels for documentation and attribution
3. Sets shell options for robust error handling
4. Installs only runtime dependencies (tcl, bedtools, bcftools, unzip)
5. Copies compiled AnnotSV from builder stage
6. Configures environment variables for proper PATH and ANNOTSV location

This multi-stage approach significantly reduces the final image size by excluding build tools and intermediate artifacts.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
