# AGENTS.md - WILDS Docker Library

## Project Overview

Curated Docker images for bioinformatics tools, maintained by Fred Hutch's Office of the Chief Data Officer (OCDO). Each image targets one primary tool and is published to DockerHub and GHCR under the `getwilds/` namespace.

## Repo Structure

```
toolname/
├── Dockerfile_X.Y.Z    # specific version → getwilds/toolname:X.Y.Z
├── Dockerfile_latest   # current version → getwilds/toolname:latest
├── CVEs_*.md           # auto-generated vulnerability reports
└── README.md           # tool documentation (required)
template/
├── Dockerfile_template # reference Dockerfile for new images
└── README.md           # reference README for new images
amd64_only_tools.txt    # tools that cannot build for linux/arm64
Makefile                # local dev commands
```

## Dockerfile Requirements

Every Dockerfile **must** include:

1. **OCI metadata labels** — title, description, version, authors (`wilds@fredhutch.org`), source URL, MIT license
2. **Shell config** — `SHELL ["/bin/bash", "-o", "pipefail", "-c"]`
3. **Pinned versions** — use `apt-cache policy` for system packages; never use `latest` in downloads
4. **Smoke test** — a `RUN` command verifying the install (e.g., `tool --version`)
5. **Cleanup** — `rm -rf /var/lib/apt/lists/*`, `mamba clean -afy`, remove tarballs, etc.

Common base images: `ubuntu:24.04`, `condaforge/miniforge3`, `bioconductor/bioconductor_docker:RELEASE_3_*`, `python:3.x-slim`. GPU-centric tools that require CUDA should use `nvidia/cuda:X.Y.Z-runtime-ubuntuXX.XX`; if they use PyTorch CUDA wheels, also add them to `amd64_only_tools.txt` (those wheels are not available for ARM64).

Target image size: a few hundred MB, max 2GB. One primary tool per image (one or two closely related companion tools are acceptable when commonly used together in workflows).

## Linting and Building

```bash
make lint IMAGE=toolname        # hadolint
make build_amd64 IMAGE=toolname # build for AMD64
make build IMAGE=toolname       # build both architectures
make validate IMAGE=toolname    # lint + build both
make clean IMAGE=toolname       # remove built images
```

ARM64 builds automatically skip tools listed in `amd64_only_tools.txt`.

## CI/CD

- **docker-update.yml** — builds/publishes to DockerHub + GHCR on push to main
- **dockerfile-linting.yml** — runs hadolint on PRs
- **docker-scout.yml** — monthly security scans, auto-generates CVE reports

## Commit and PR Conventions

- Imperative mood: "Add samtools image", "Update GATK to v4.5", "Fix hadolint warning in picard"
- PR titles: `Add [Tool] Docker image (vX.Y.Z)` or `Update [Tool] to vX.Y.Z`
- Tag reviewers: @emjbishop or @tefirman

## README Standards

Each tool README needs: description and official docs link, available versions table, platform availability, Docker and Apptainer pull commands, usage examples, installed components list, security/CVE info, and contributing link.

## Agent Skills

Reusable task-specific instructions live in [.agents/skills/](.agents/skills/). Each `SKILL.md` is a self-contained recipe an agent can follow:

- `new-image` — create a new Docker image for a bioinformatics tool
- `update-image` — update an existing image to a new version
- `fix-cves` — identify and remediate CVEs in an existing image
- `pr-description` — draft a PR description from the current branch
