---
name: new-image
description: Create a new Docker image for a bioinformatics tool
argument-hint: <tool-name>
allowed-tools: Bash, Read, Glob, Grep, WebSearch, WebFetch
---

# Create a New Docker Image

Scaffold and build a new WILDS Docker image for an open-source bioinformatics tool.

## Steps

### 1. Research the Tool

Before writing any files, research the tool to understand:

- What it does and what it is used for
- The latest stable version available
- How it is typically installed (apt, conda/mamba, pip, compiled from source, pre-built binary/JAR, etc.)
- What base image is most appropriate (`ubuntu:24.04`, `condaforge/miniforge3`, `bioconductor/bioconductor_docker`, `python:3.x-slim`, etc.)
- Its official homepage and citation information
- What dependencies it requires

### 2. Create the Tool Directory and Dockerfile

- Create a new directory named after the tool (lowercase, hyphens for multi-word names)
- Read `template/Dockerfile_template` first as the formatting reference
- Create `Dockerfile_latest` following ALL Dockerfile requirements from `AGENTS.md`:
  - OCI metadata labels (title, description, version, authors, source URL, MIT license)
  - `SHELL ["/bin/bash", "-o", "pipefail", "-c"]`
  - Pinned versions for system packages using `apt-cache policy`
  - A smoke test `RUN` command verifying the install (e.g., `tool --version`)
  - Cleanup steps (`rm -rf /var/lib/apt/lists/*`, `mamba clean -afy`, remove tarballs, etc.)
- Also create `Dockerfile_X.Y.Z` for the specific version (may be identical to latest)
- Target image size: a few hundred MB, max 2GB. One primary tool per image.

### 3. Create the README

- Read `template/README.md` first as the formatting reference
- Fill in all standard sections: description, available versions, image details, citation, Docker/Apptainer usage, example commands, Dockerfile structure, security/CVE info, and source repository
- Remove any optional sections that do not apply
- Remove ALL HTML comments and template instructions from the final README
- Provide realistic example commands

### 4. Lint the Dockerfile

Run `make lint IMAGE=<toolname>` to check for hadolint issues. Fix any warnings or errors before proceeding.

### 5. Build and Test

Run `make build_amd64 IMAGE=<toolname>` to verify the image builds successfully. Diagnose and fix any failures, then re-run until it passes.

### 6. Summary

After all steps pass, report:

- The tool version packaged
- The base image used
- The installation method chosen
- Any notable decisions or trade-offs made
- Confirmation that lint and build passed
