# [Tool Name]

<!-- Brief 1-2 sentence description of what the tool does -->
This directory contains Docker images for [Tool Name], a [brief description of tool's purpose and functionality].

## Available Versions

<!-- List all available versions with links to Dockerfiles and vulnerability reports -->
<!-- Update the tool name and versions as appropriate -->
- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/toolname/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/toolname/CVEs_latest.md) )
- `X.Y.Z` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/toolname/Dockerfile_X.Y.Z) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/toolname/CVEs_X.Y.Z.md) )

<!-- Add more versions as needed -->

## Image Details

<!-- Describe what base image is used and what's included in the image -->
These Docker images are built from [Base Image Name/Version] and include:

- [Tool Name] vX.Y.Z: [Brief description of what this tool does]
- [Dependency 1]: [Why it's included]
- [Dependency 2]: [Why it's included]
<!-- Add any other significant components -->

<!-- Optional: Add notes about design philosophy -->
The images are designed to be minimal and focused on [tool name] with its essential dependencies.

<!-- Optional: If the image includes custom scripts, mention them here -->
<!-- Example: -->
<!-- The image includes a custom analysis script (`tool_analysis.R`) that provides a ready-to-use workflow for [specific use case]. -->

## Usage

### Docker

```bash
# Pull the latest version
docker pull getwilds/toolname:latest

# Or pull a specific version
docker pull getwilds/toolname:X.Y.Z

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/toolname:latest
```

### Singularity/Apptainer

```bash
# Pull the latest version
apptainer pull docker://getwilds/toolname:latest

# Or pull a specific version
apptainer pull docker://getwilds/toolname:X.Y.Z

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/toolname:latest
```

### Example Commands

<!-- Provide 3-5 practical examples of how to use the tool -->
<!-- Include both Docker and Apptainer examples -->
<!-- Use realistic file paths and clear explanations -->

```bash
# Example 1: [Brief description of what this does]
docker run --rm -v /path/to/data:/data getwilds/toolname:latest \
  toolname [command] [options] /data/input.file > /data/output.file

# Example 2: [Brief description of what this does]
docker run --rm -v /path/to/data:/data getwilds/toolname:latest \
  toolname [command] --option1 value1 --option2 value2 /data/input.file

# Alternatively using Apptainer
apptainer run --bind /path/to/data:/data docker://getwilds/toolname:latest \
  toolname [command] [options] /data/input.file > /data/output.file

# ... or a local SIF file via Apptainer
apptainer run --bind /path/to/data:/data toolname_latest.sif \
  toolname [command] [options] /data/input.file
```

<!-- Optional: If your tool has specific quirks or important notes, add a section -->
<!-- Example: -->
<!--
## Important Notes

### [Topic, e.g., "Temporary Files", "Memory Requirements", "Java Heap Size"]

[Explanation of the issue and how to handle it]

Example:
```bash
# [Command showing how to address the issue]
```
-->

<!-- Optional: If the image includes custom scripts with parameters, document them -->
<!--
## Script Parameters

### [Script Name] (`script_name.R`)

The included `script_name.R` script accepts the following parameters:

- `--param1`: [Description] (required/optional, default: value)
- `--param2`: [Description] (required/optional, default: value)
- `--param3`: [Description] (required/optional, default: value)

Example usage:
```bash
docker run --rm -v /path/to/data:/data getwilds/toolname:latest \
  Rscript /usr/local/bin/script_name.R \
  --param1=/data/input.txt \
  --param2=value \
  --output=/data/results
```

### Outputs

The script produces the following outputs:

1. `*_output1.ext`: [Description of what this contains]
2. `*_output2.ext`: [Description of what this contains]
-->

## Dockerfile Structure

<!-- Describe the general structure and build process of the Dockerfile -->
The Dockerfile follows these main steps:

1. Uses [Base Image] as the base image
2. Adds metadata labels for documentation and attribution
3. [Installation step 1, e.g., "Installs system dependencies with pinned versions"]
4. [Installation step 2, e.g., "Downloads and builds Tool from source"]
5. [Additional steps as applicable]
6. Performs cleanup to minimize image size

<!-- Optional: Mention any special considerations -->
<!-- Example: "The JAR file is placed in /usr/toolname/ to ensure persistence in Apptainer conversions" -->

## Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in [this directory](https://github.com/getwilds/wilds-docker-library/blob/main/toolname), which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.

---

<!--
==============================================================================
README TEMPLATE USAGE NOTES
==============================================================================

This template is designed to maintain consistency across WILDS Docker images.
Follow these guidelines:

1. REPLACE ALL PLACEHOLDERS:
   - [Tool Name] - The name of your tool
   - [toolname] - Lowercase version for URLs/paths
   - X.Y.Z - Actual version numbers
   - [command], [options], etc. - Actual tool commands

2. REMOVE OPTIONAL SECTIONS if they don't apply to your tool:
   - Important Notes
   - Script Parameters
   - Outputs
   - Any commented examples you don't need

3. KEEP CONSISTENT FORMATTING:
   - Use sentence case for section headers
   - Include both Docker and Apptainer examples
   - Provide realistic file paths in examples
   - Keep code blocks properly formatted

4. EXAMPLES SHOULD BE REALISTIC:
   - Show actual commands users would run
   - Use meaningful file names (not foo.txt)
   - Include common use cases for your tool
   - Explain what each example does

5. MAINTAIN STANDARD SECTIONS (keep these even if minimal):
   - Available Versions
   - Image Details
   - Usage (Docker/Apptainer)
   - Example Commands
   - Dockerfile Structure
   - Security Scanning and CVEs
   - Source Repository

6. CROSS-REFERENCE EXAMPLES:
   - Simple tool: samtools/README.md
   - Tool with scripts: deseq2/README.md
   - Java application: picard/README.md
   - Tool with special notes: samtools/README.md (temp files section)

7. DELETE THIS SECTION when creating your actual README!

==============================================================================
-->
