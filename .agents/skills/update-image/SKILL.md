---
name: update-image
description: Update an existing WILDS Docker image to a new version
argument-hint: <tool-name> [version]
allowed-tools: Bash, Read, Glob, Grep, WebSearch, WebFetch
---

# Update an Existing Docker Image

Update a WILDS Docker image to a new version. The argument can be:

- Just a tool name (e.g., `samtools`) — automatically find and update to the latest available version
- A tool name and version (e.g., `samtools 1.21`) — update to that specific version

## Steps

### 1. Understand the Current State

- Read the existing `Dockerfile_latest` in the tool's directory to understand the current version, base image, installation method, and structure
- Read the tool's `README.md` to understand what is documented
- Identify the current version from the Dockerfile (look at download URLs, version labels, etc.)

### 2. Determine the Target Version

- If a specific version was provided, use that
- If only a tool name was provided, research the tool's releases to find the latest stable version
- If the tool is already at the latest version, report that and stop — no changes needed

### 3. Create or Update Version-Specific Dockerfile

- If a `Dockerfile_X.Y.Z` for the NEW version does not exist, create one based on `Dockerfile_latest` with the new version number
- If the old `Dockerfile_latest` pointed to a version that does not have its own pinned Dockerfile yet, consider whether one should be created for the old version before updating (check what version-specific files already exist)

### 4. Update Dockerfile_latest

- Update the version in download URLs, build commands, and any version-specific paths
- Update the `org.opencontainers.image.version` label if it contains the version number (keep it as "latest" if that is the convention used)
- Keep the same installation method and structure — do not refactor unless necessary
- Ensure all Dockerfile requirements from `AGENTS.md` are still met

### 5. Update the README

- Add the new version to the "Available Versions" table
- Update any version references in the "Image Details" section
- Do NOT remove old versions from the table — they should remain listed

### 6. Lint and Build

- Run `make lint IMAGE=<toolname>` and fix any issues
- Run `make build_amd64 IMAGE=<toolname>` and fix any build failures

### 7. Summary

Report what changed:

- Previous version vs. new version
- Files created or modified
- Any issues encountered and how they were resolved
- Confirmation that lint and build passed
