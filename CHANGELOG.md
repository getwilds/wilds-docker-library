# Changelog

All notable changes to the WILDS Docker Library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-01-28

Initial release of the WILDS Docker Library.

### Added

- **47 bioinformatics tool images** including AnnotSV, ANNOVAR, BCFtools, BEDtools, BWA, Cell Ranger, DELLY, DESeq2, GATK, GLIMPSE2, HISAT2, Manta, Picard, Samtools, Scanpy, STAR, Strelka, and many more (see [README](README.md) for the full list)
- **Multi-platform support** for both linux/amd64 and linux/arm64 on most images, with documented exceptions for AMD64-only tools
- **Automated CI/CD workflows** via GitHub Actions:
  - Docker image building and publishing to DockerHub and GitHub Container Registry
  - Dockerfile linting with hadolint on pull requests
  - Monthly security vulnerability scanning with Docker Scout
- **Security vulnerability reports** (`CVEs_*.md`) auto-generated for every image
- **Developer tooling:**
  - Makefile for local linting, building, and validation (`make lint`, `make build`, `make validate`)
  - Template Dockerfile with comprehensive inline documentation
  - Contributing guidelines, Code of Conduct, and issue/PR templates
- **Per-tool documentation** with usage examples for both Docker and Apptainer/Singularity
