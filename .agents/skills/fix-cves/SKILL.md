---
name: fix-cves
description: Identify and remediate CVEs in WILDS Docker images
argument-hint: <tool-name> | worst | (blank)
allowed-tools: Bash, Read, Glob, Grep
---

# Fix CVEs in Docker Images

Identify and remediate vulnerabilities in WILDS Docker images. The argument can be:

- A specific tool name (e.g., `samtools`) — fix CVEs for that image
- `worst` or left blank — scan all CVE reports, rank images by severity, and fix the worst offenders

## Steps

### 1. Identify Target Images

**If a specific tool was provided:**

- Read `<tool>/CVEs_latest.md` to understand the current vulnerability landscape

**If `worst` or blank:**

- Read all `*/CVEs_latest.md` files across the repo
- Rank images by CVE severity (Critical > High > Medium > Low) and count
- Present a summary table of the top 5-10 worst images to the user
- Ask the user which image(s) to fix, or proceed with the worst one

### 2. Analyze CVE Sources

For each target image, determine where the vulnerabilities come from by reading the CVE report carefully:

- **Base image CVEs** — shown in the "Base Image" section of the report; fixed by upgrading the base image (e.g., `ubuntu:22.04` to `ubuntu:24.04`, or refreshing to a newer digest)
- **Tool/dependency CVEs** — the difference between total CVEs and base image CVEs; come from the tool itself or packages installed on top of the base image
- **Check the "Recommendations" section** for suggested base image updates

### 3. Determine Fixable Actions

Read the tool's `Dockerfile_latest` and consider these remediation strategies in order of impact:

1. **Upgrade the base image** if the report recommends a refreshed or updated base image
2. **Upgrade the tool version** if a newer version exists that might pull in fewer vulnerable dependencies
3. **Remove unnecessary packages** — check if build-only dependencies are left in the final image
4. **Add `apt-get upgrade`** as a last resort for system-level patches (after `apt-get update`, before installing packages)
5. **Switch to a slimmer base** if appropriate (e.g., `python:3.x` to `python:3.x-slim`)

### 4. Apply Fixes

- Make changes to `Dockerfile_latest` and any corresponding `Dockerfile_X.Y.Z`
- Preserve the existing installation method and structure as much as possible
- Ensure all Dockerfile requirements from `AGENTS.md` are still met

### 5. Lint and Build

- Run `make lint IMAGE=<toolname>` and fix any issues
- Run `make build_amd64 IMAGE=<toolname>` and fix any build failures

### 6. Assess Impact

After a successful build, if Docker Scout is available locally, run:

```bash
docker scout quickview getwilds/<toolname>:latest-amd64
```

to compare the new vulnerability count against the old report. If Docker Scout is not available locally, note that the user should check after pushing to verify improvement.

### 7. Summary

Report:

- Which image(s) were fixed
- What changes were made (base image upgrade, tool upgrade, dependency removal, etc.)
- CVE counts before the fix (from the report)
- Expected impact of the changes
- Any CVEs that are NOT fixable through Dockerfile changes (e.g., vulnerabilities in the tool's own code that require an upstream fix)
- Confirmation that lint and build passed
