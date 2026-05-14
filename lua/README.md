# Lua

This directory contains Docker images for Lua, a powerful, efficient, lightweight, embeddable scripting language. The image provides a standalone Lua interpreter suitable for running Lua scripts in any containerized workflow. It also bundles the Lua libraries (`luaposix` and `luafilesystem`) needed to run [Lmod](https://lmod.readthedocs.io/) — the Lua-based environment modules system commonly found on HPC clusters — when an Lmod install is provided by the host and bind-mounted into the container.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/lua/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/lua/CVEs_latest.md) )
- `5.3.6` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/lua/Dockerfile_5.3.6) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/lua/CVEs_5.3.6.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- Lua 5.3.6: A lightweight, embeddable scripting language
- luaposix: POSIX bindings for Lua (also a runtime dependency of Lmod)
- luafilesystem (lfs): Filesystem manipulation library for Lua (also a runtime dependency of Lmod)

The images are intentionally minimal and contain only the Lua interpreter and a couple of widely-used libraries. Lmod itself is **not** installed; if you want to use Lmod with this image, the expectation is that Lmod is provided by the host (e.g., bind-mounted from a shared HPC filesystem) and executed using the Lua interpreter inside the container. If you are not using Lmod, the image works as a plain Lua 5.3 runtime.

## Citation

If you use Lua in your research, please credit the original authors:

```
Ierusalimschy, R., de Figueiredo, L. H., & Celes, W. (1996). Lua: An extensible
extension language. Software: Practice and Experience, 26(6), 635-652.
```

**Tool homepage:** https://www.lua.org/

**Lmod homepage:** https://lmod.readthedocs.io/

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/lua:latest

# Or pull a specific version
docker pull getwilds/lua:5.3.6

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/lua:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/lua:latest

# Or pull a specific version
apptainer pull docker://getwilds/lua:5.3.6

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/lua:latest
```

### Example Commands

```bash
# Check the Lua version
docker run --rm getwilds/lua:latest lua -v

# Run a Lua script from the host
docker run --rm -v /path/to/scripts:/scripts getwilds/lua:latest \
  lua /scripts/myscript.lua

# Verify the bundled Lua libraries are present (useful when pairing with Lmod)
docker run --rm getwilds/lua:latest \
  lua -e "require('posix'); require('lfs'); print('libraries loaded')"

# Optional: if you want to use a host-provided Lmod install (e.g. /app/lmod),
# bind-mount it and invoke it using the Lua provided by this container
apptainer exec --bind /app/lmod:/app/lmod docker://getwilds/lua:latest \
  lua /app/lmod/libexec/lmod bash list
```

## Optional: Using with Lmod on an HPC

If your workflow needs Lmod, this image can be paired with a host-provided Lmod installation — Lmod is **not** required to use the image otherwise. A typical pattern with Apptainer is to bind-mount the cluster's Lmod tree (and its module file paths) into the container, then invoke `lmod` using the Lua interpreter inside the image:

```bash
# Bind the Lmod install and module tree from the host into the container
apptainer exec \
  --bind /app/lmod:/app/lmod \
  --bind /app/modulefiles:/app/modulefiles \
  docker://getwilds/lua:latest \
  bash -c 'export MODULEPATH=/app/modulefiles; \
           eval "$(lua /app/lmod/libexec/lmod bash load samtools)"; \
           samtools --version'
```

Adjust the bind paths to match your cluster's Lmod layout.

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu 24.04 as the base image
2. Adds metadata labels for documentation and attribution
3. Dynamically determines and pins the latest security-patched versions of Lua 5.3 and its companion libraries
4. Installs `lua5.3`, `liblua5.3-dev`, `lua-posix`, and `lua-filesystem` from the Ubuntu archive
5. Adds `lua` and `luac` symlinks under `/usr/bin` so generic `lua` invocations resolve correctly
6. Performs cleanup to minimize image size
7. Runs a smoke test that loads `posix` and `lfs` to verify the runtime and its bundled libraries (which Lmod also requires) are working

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/lua), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
