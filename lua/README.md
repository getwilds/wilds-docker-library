# Lua

This directory contains Docker images for Lua, a powerful, efficient, lightweight, embeddable scripting language. The image is configured for use in HPC environments where [Lmod](https://lmod.readthedocs.io/) (the Lua-based environment modules system) is provided by the host and invoked from within the container.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/lua/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/lua/CVEs_latest.md) )
- `5.3.6` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/lua/Dockerfile_5.3.6) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/lua/CVEs_5.3.6.md) )

## Image Details

These Docker images are built from Ubuntu 24.04 and include:

- Lua 5.3.6: A lightweight, embeddable scripting language used by Lmod for module file evaluation
- luaposix: POSIX bindings for Lua, required by Lmod at runtime
- luafilesystem (lfs): Filesystem manipulation library for Lua, required by Lmod at runtime

The images are intentionally minimal — Lmod itself is **not** installed, since it is expected to be provided by the host HPC environment (e.g., bind-mounted into the container or available on a shared filesystem). The images exist to provide a Lua interpreter compatible with Lmod's runtime requirements when no system Lua is available inside the container.

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

# Verify the Lmod-required Lua libraries are present
docker run --rm getwilds/lua:latest \
  lua -e "require('posix'); require('lfs'); print('ready for lmod')"

# Apptainer: bind the host's Lmod install (e.g. /app/lmod) and invoke it
# using the Lua provided by this container
apptainer exec --bind /app/lmod:/app/lmod docker://getwilds/lua:latest \
  lua /app/lmod/libexec/lmod bash list
```

## Using with Lmod on an HPC

This image is designed to be paired with a host-provided Lmod installation. A typical pattern with Apptainer is to bind-mount the cluster's Lmod tree (and its module file paths) into the container, then invoke `lmod` using the Lua interpreter inside the image:

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
7. Runs a smoke test that loads `posix` and `lfs` to verify the runtime is ready for Lmod

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/lua), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
