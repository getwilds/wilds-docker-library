---
name: multi-stage-cves
description: Convert a WILDS Docker image to a multi-stage build to eliminate CVEs from build-only tooling
argument-hint: <tool-name>
allowed-tools: Bash, Read, Edit, Write, Glob, Grep
---

# Convert a WILDS Docker Image to a Multi-Stage Build

Many WILDS images install `build-essential`, `-dev` header packages, `autoconf`/`automake`, etc. directly into the final image so they can compile a tool from source.

Splitting the Dockerfile into a `builder` stage (compiles from source) and a minimal final stage (runtime shared libs plus copied binaries only) removes nearly all CVEs that come from that build tooling.

This does not change the tool version or its behavior.

This is the pattern already applied to the `samtools` (PR #383), `bwa` (PR #384), and `bedtools` (PR #385) images.

See those PRs for worked examples of the before/after Dockerfile diff.

## When this applies

Good fit:
- The Dockerfile compiles something with `make`/`make install` (or similar) and leaves `build-essential`, `gcc`, `-dev` packages, `autoconf`, `automake`, etc. installed in the same, single-stage image.
- The CVE report's total count is far higher than its "Base Image" section count.
- The gap is coming from build tooling, not the base OS.

Not a fit (fall back to the general `fix-cves` skill instead):
- The image installs everything via apt/mamba/pip with no source compilation.
- Vulnerabilities are dominated by the base image itself.
- Bump the base image instead.
- The tool's own runtime code carries the CVE.
- There's no Dockerfile fix available.

## Steps

### 1. Confirm the branch and read current state

- Expect (or create) a branch named `fix-<toolname>-cves`.
- Read `<tool>/CVEs_latest.md` for the current vulnerability counts and the "Base Image" breakdown.
- Read `<tool>/Dockerfile_latest` and every `<tool>/Dockerfile_X.Y.Z`.
- All versioned Dockerfiles need the same treatment, not just `latest`.

### 2. Split into builder and final stages

For each Dockerfile:

- **Builder stage**: `FROM <base> AS builder`, `SHELL` directive, and the `apt-get install` block for build-only packages.
- Build-only packages include `build-essential`, `wget`, `-dev` headers, `autoconf`, `automake`, etc., each pinned via `apt-cache policy | grep Candidate`.
- Download/extract/`configure && make && make install` the source-built tool(s) here.
- Clean up source tarballs/dirs at the end of this stage.
- **Final stage**: fresh `FROM <base>` with the OCI metadata `LABEL`s, the `SHELL` directive, and an `apt-get install` block for **runtime-only** packages.
- Swap each `-dev`/static package for its runtime shared-library equivalent:
  - `libncurses-dev` becomes `libncursesw6`
  - `zlib1g-dev` becomes `zlib1g`
  - `libbz2-dev` becomes `libbz2-1.0`
  - `liblzma-dev` becomes `liblzma5`
  - `libssl-dev` becomes `libssl3t64`
  - `libcurl4-gnutls-dev` becomes `libcurl3t64-gnutls`
- Drop `build-essential`, `autoconf`, `automake`, `wget` entirely, unless the tool needs `wget` at runtime.
- Keep any apt-installed non-source tool (e.g. `bedtools`) in this stage.
- `COPY --from=builder /usr/local/bin/<binary> /usr/local/bin/<binary>` for each compiled binary needed at runtime.
- Keep the smoke test (`RUN <tool> --version [&& <companion> --version]`), `WORKDIR`, and `CMD`/`HEALTHCHECK` in the final stage, same as before.

Preserve tool versions, installation URLs, and structure exactly.

This is a build-topology change, not a version bump.

### 3. Lint and build

- Run `make lint IMAGE=<toolname>` and fix any issues.
- If hadolint isn't installed locally, run `docker run --rm -i hadolint/hadolint < <tool>/Dockerfile_X` per file instead.
- Run `make build_amd64 IMAGE=<toolname>` and fix any build failures.
- Confirm the smoke test output for every affected Dockerfile version.

### 4. Assess impact

If Docker Scout is available locally:

```bash
docker scout quickview getwilds/<toolname>:latest-amd64
```

Compare High/Medium/Low counts against `CVEs_latest.md`.

Expect High to drop to near zero and Medium to drop by an order of magnitude.

Remaining counts are typically inherited from the base image itself and not fixable here.

### 5. Update the README

In `<tool>/README.md`:
- **Security Features** section: mention that the multi-stage build keeps compilers and dev headers out of the final image.
- **Dockerfile Structure** section: rewrite as a build-stage / final-stage list, ending with a line noting this reduces image size and attack surface.
- Match the wording style used in the `bwa` and `bedtools` READMEs in PRs #384 and #385.

### 6. Optional: verify against the WILDS WDL Library

If the tool has a corresponding module in the WILDS WDL Library, offer to build and tag a local image for a real test run.

- Build the image locally and tag it as `getwilds/<toolname>:<version>-local`.
- The user updates the `docker` runtime variable in the relevant `ww-<toolname>` module to point at that tag.
- The user runs that module's test suite against the new image before it gets published.

Only do this if the user asks for it or the WDL module clearly exists.

Do not assume every image has one.

### 7. Summary

Report:
- Which Dockerfile(s) were converted (latest plus each versioned file)
- The before/after CVE counts (High/Medium/Low) from the report vs. Docker Scout
- Confirmation lint and build passed for every Dockerfile
- Any remaining CVEs and why they aren't fixable via this approach
- Reminder that changes are staged for the user to commit (do not commit unless explicitly asked)
