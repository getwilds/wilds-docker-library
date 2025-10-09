#!/usr/bin/env python
# -*-coding:utf-8 -*-
"""
@File    :   docker_update.py
@Time    :   2025/04/17 12:55:55
@Author  :   Taylor Firman
@Version :   v0.1
@Contact :   tfirman@fredhutch.org
@Desc    :   This script automates the process of building, pushing, and updating Docker images.

1. Finding changed Dockerfiles
2. Building and pushing Docker images to both GitHub Container Registry and DockerHub
3. Generating vulnerability reports
4. Updating DockerHub repository descriptions

Usage:
    python docker_update.py [directory]

    If directory is provided, only images in that directory will be processed.
    If no directory is provided, changed files from the git diff will be used.

Environment variables:
    GITHUB_REF_NAME: The branch or ref name
    DOCKERHUB_USER: DockerHub username for authentication
    DOCKERHUB_PW: DockerHub password for authentication
"""

import os
import sys
import glob
import json
import logging
import requests
from datetime import datetime
import git
from utils import run_command, parse_scout_quickview

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("docker-update")

# Size limit for Docker Scout scanning (3GB in bytes)
DOCKER_SCOUT_SIZE_LIMIT = 3 * 1024 * 1024 * 1024


def get_image_size(image_name):
    """
    Get the size of a Docker image in bytes using docker manifest inspect.

    Args:
        image_name: Full image name (e.g., ghcr.io/getwilds/tool:tag)

    Returns:
        Size in bytes, or None if unable to determine
    """
    try:
        result = run_command(
            f"docker manifest inspect {image_name}", capture_output=True
        )
        manifest = json.loads(result)

        total_size = 0
        if "config" in manifest and "size" in manifest["config"]:
            total_size += manifest["config"]["size"]

        if "layers" in manifest:
            for layer in manifest["layers"]:
                if "size" in layer:
                    total_size += layer["size"]

        return total_size
    except Exception as e:
        logger.warning(f"Could not determine size for {image_name}: {e}")
        return None


def format_size(size_bytes):
    """Format size in bytes to human readable format."""
    if size_bytes is None:
        return "unknown"

    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def setup_buildx():
    """Set up Docker buildx for multi-platform builds."""
    logger.info("Setting up Docker buildx for multi-platform builds...")

    try:
        # Create and use a new builder instance
        run_command("docker buildx create --name multiplatform --use", check=False)

        # Bootstrap the builder (downloads necessary components)
        run_command("docker buildx inspect --bootstrap")

        logger.info("Docker buildx setup completed successfully")
        return True
    except Exception as e:
        logger.warning(f"Failed to setup buildx: {e}")
        logger.info("Falling back to single-platform builds")
        return False


def find_changed_files(specified_dir=None):
    """
    Find Dockerfiles and README files that have changed.

    Args:
        specified_dir: If provided, only find files in this directory

    Returns:
        Tuple of (docker_files, readme_files, affected_dirs)
    """
    docker_files = []
    readme_files = []

    repo = git.Repo(".")

    if specified_dir:
        logger.info(f"Processing specified directory: {specified_dir}")

        # Skip template directory
        if specified_dir == "template":
            logger.info("Skipping template directory - not a real Docker image")
            return [], [], []

        # Verify the directory exists
        if not os.path.isdir(specified_dir):
            logger.error(f"Error: Directory '{specified_dir}' does not exist.")
            sys.exit(1)

        # Find all Dockerfiles in the specified directory
        docker_files = glob.glob(f"{specified_dir}/Dockerfile_*")
        docker_files.sort()

        if not docker_files:
            logger.info(f"No Dockerfiles found in '{specified_dir}'.")
        else:
            logger.info(f"Dockerfiles to process: {docker_files}")

        # Find README.md in the specified directory
        readme_path = os.path.join(specified_dir, "README.md")
        if os.path.isfile(readme_path):
            readme_files = [readme_path]
            logger.info(f"README.md found in '{specified_dir}'.")

        # Only one directory is affected in manual mode
        affected_dirs = [specified_dir]

    else:
        logger.info("Processing push event - detecting changed files")
        diff_target = f"{repo.head.commit.parents[0].hexsha}..{repo.head.commit.hexsha}"

        # Get list of changed files
        changed_files = [
            item
            for item in repo.git.diff(diff_target, name_only=True).split("\n")
            if item
        ]

        logger.info(f"Changed files: {changed_files}")

        # Filter for Dockerfiles
        docker_files = [f for f in changed_files if "Dockerfile_" in f]
        if not docker_files:
            logger.info("No Dockerfile changes detected.")
        else:
            logger.info(f"Changed Dockerfiles: {docker_files}")

        # Filter for README files
        readme_files = [f for f in changed_files if f.endswith("README.md")]
        if not readme_files:
            logger.info("No README changes detected.")
        else:
            logger.info(f"Changed READMEs: {readme_files}")

        # Create a list of affected directories
        all_files = docker_files + readme_files
        affected_dirs = list(set(os.path.dirname(f) for f in all_files if f))

        if not affected_dirs:
            logger.info("No affected directories.")
        else:
            logger.info(f"Affected directories: {affected_dirs}")

    return docker_files, readme_files, affected_dirs


def build_and_push_images(docker_files):
    """
    Build, push Docker images, and generate vulnerability reports.

    Args:
        docker_files: List of Dockerfile paths to process

    Returns:
        List of CVE report files generated
    """
    if not docker_files:
        logger.info("No Docker files to process")
        return []

    # Set up buildx for multi-platform builds
    buildx_available = setup_buildx()

    cve_files = []

    for dockerfile in docker_files:
        if not os.path.isfile(dockerfile):
            logger.warning(f"File not found: {dockerfile}")
            continue

        # Extract tool name and tag from path
        tool_name = os.path.dirname(dockerfile)
        tag = os.path.basename(dockerfile).split("_")[-1]

        logger.info(f"Building image for {tool_name}:{tag}")

        if buildx_available:
            # Build AMD64 first to check size
            logger.info("Building AMD64 image...")
            run_command(
                f"docker buildx build "
                f"--platform linux/amd64 "
                f"-t getwilds/{tool_name}:{tag} "
                f"-t ghcr.io/getwilds/{tool_name}:{tag} "
                f"-f {dockerfile} "
                f"--provenance=false "
                f"--push ."
            )

            # Check the size of the built image (same logic as Docker Scout)
            image_size = get_image_size(f"getwilds/{tool_name}:{tag}")
            if image_size is not None and image_size > DOCKER_SCOUT_SIZE_LIMIT:
                logger.info(
                    f"Image is large ({format_size(image_size)}), skipping ARM64 build to avoid disk space issues"
                )
            else:
                logger.info(
                    f"Image is manageable ({format_size(image_size) if image_size else 'unknown'}), building ARM64..."
                )

                # Build multi-platform (this will update the manifest to include both platforms)
                run_command(
                    f"docker buildx build "
                    f"--platform linux/amd64,linux/arm64 "
                    f"-t getwilds/{tool_name}:{tag} "
                    f"-t ghcr.io/getwilds/{tool_name}:{tag} "
                    f"-f {dockerfile} "
                    f"--provenance=false "
                    f"--push ."
                )

            # Final cleanup
            logger.info("Final cleanup...")
            run_command("docker buildx prune -f", check=False)

        else:
            # Fallback to single-platform build
            logger.info("Building single-platform image (linux/amd64)")
            run_command(
                f"docker build --platform linux/amd64 -t getwilds/{tool_name}:{tag} -f {dockerfile} ."
            )

            # Push to DockerHub
            run_command(f"docker push getwilds/{tool_name}:{tag}")

            # Tag the image for GitHub Container Registry
            run_command(
                f"docker tag getwilds/{tool_name}:{tag} ghcr.io/getwilds/{tool_name}:{tag}"
            )

            # Push to GitHub Container Registry
            run_command(f"docker push ghcr.io/getwilds/{tool_name}:{tag}")

        # Update Docker Scout CVE markdown file
        cve_file = f"{tool_name}/CVEs_{tag}.md"
        container = f"ghcr.io/getwilds/{tool_name}:{tag}"

        with open(cve_file, "w") as f:
            pst_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S PST")
            f.write(f"# Vulnerability Report for getwilds/{tool_name}:{tag}\n\n")
            f.write(f"Report generated on {pst_now}\n\n")
            f.write("## Platform Coverage\n\n")
            f.write("This vulnerability scan covers the **linux/amd64** platform. ")
            f.write(
                "While this image also supports linux/arm64, the security analysis "
            )
            f.write(
                "focuses on the AMD64 variant as it represents the majority of deployment targets. "
            )
            f.write(
                "Vulnerabilities between architectures are typically similar for most bioinformatics applications.\n\n"
            )

        # Check image size before running Docker Scout
        image_size = get_image_size(container)
        if image_size is not None and image_size > DOCKER_SCOUT_SIZE_LIMIT:
            logger.info(
                f"Image {container} is {format_size(image_size)}, exceeding limit of {format_size(DOCKER_SCOUT_SIZE_LIMIT)}. Skipping Docker Scout scan."
            )

            # Write size limit message to CVE file
            with open(cve_file, "a") as f:
                f.write("## ⚠️ Scan Skipped - Image Too Large\n\n")
                f.write(
                    "Docker Scout scan was skipped for this image because it exceeds the size limit.\n\n"
                )
                f.write(f"**Image size:** {format_size(image_size)}\n")
                f.write(f"**Size limit:** {format_size(DOCKER_SCOUT_SIZE_LIMIT)}\n\n")
                f.write(
                    "Large images can cause timeouts and resource exhaustion in CI/CD environments. "
                )
                f.write(
                    "If you need a vulnerability scan for this image, please run it manually:\n\n"
                )
                f.write("```bash\n")
                f.write(f"docker scout quickview {container} --platform linux/amd64\n")
                f.write("```\n")
        else:
            try:
                result = run_command(
                    f"docker scout quickview {container} --platform linux/amd64",
                    capture_output=True,
                )

                # Parse the scout output into clean markdown
                parsed_markdown = parse_scout_quickview(result)

                with open(cve_file, "a") as f:
                    f.write(parsed_markdown)

                logger.info(f"Successfully generated CVE report for {tool_name}:{tag}")
            except Exception as e:
                logger.warning(f"Docker Scout failed for {tool_name}:{tag}: {e}")
                # Write a fallback message to the CVE file
                with open(cve_file, "a") as f:
                    f.write("**Docker Scout scan failed for this image**\n\n")
                    f.write(f"Error: {str(e)}\n\n")

        # Replace ghcr.io/getwilds with getwilds in the report
        with open(cve_file, "r") as f:
            content = f.read()

        with open(cve_file, "w") as f:
            f.write(content.replace("ghcr.io/getwilds/", "getwilds/"))

        logger.info(
            f"Successfully generated vulnerability report for getwilds/{tool_name}:{tag}"
        )

        # Add CVE file to manifest for later commit
        cve_files.append(cve_file)

        # Clean up Docker images to save space
        run_command("docker system prune -af", check=False)

    # Write CVE files to manifest for commit_cve_reports.py
    if cve_files:
        with open(".cve_manifest.txt", "w") as f:
            for cve_file in cve_files:
                f.write(f"{cve_file}\n")
        logger.info(f"Written {len(cve_files)} CVE files to manifest")
    else:
        logger.info("No CVE files generated")

    return cve_files


def update_dockerhub_descriptions(affected_dirs):
    """
    Update DockerHub repository descriptions for affected directories.

    Args:
        affected_dirs: List of directory paths to process
    """
    if not affected_dirs:
        logger.info("No directories to update descriptions for")
        return

    # Get DockerHub token
    auth_payload = {
        "username": os.environ.get("DOCKERHUB_USER"),
        "password": os.environ.get("DOCKERHUB_PW"),
    }
    response = requests.post(
        "https://hub.docker.com/v2/users/login/", json=auth_payload
    )
    response.raise_for_status()
    token = response.json().get("token")

    if not token:
        logger.error("Failed to get DockerHub token. Check your credentials.")
        logger.error(f"Response was: {response.text}")
        return

    logger.info("Successfully logged in to DockerHub")

    # Process each affected directory
    for directory in affected_dirs:
        # Skip if it's not a valid directory
        if not os.path.isdir(directory):
            logger.info(f"Skipping {directory}: not a valid directory")
            continue

        # Skip template directory
        if directory == "template":
            logger.info(f"Skipping {directory}: template directory")
            continue

        repo_name = os.path.basename(directory)
        logger.info(f"Processing repository: getwilds/{repo_name}")

        # Check for README.md
        readme_path = os.path.join(directory, "README.md")
        if not os.path.isfile(readme_path):
            logger.info(
                f"Warning: {readme_path} not found, skipping full description update"
            )
            full_desc = ""
        else:
            with open(readme_path, "r") as f:
                full_desc = f.read()

        # Check for Dockerfile_latest to extract short description
        dockerfile_latest = os.path.join(directory, "Dockerfile_latest")
        if not os.path.isfile(dockerfile_latest):
            logger.info(
                f"Warning: {dockerfile_latest} not found, skipping short description update"
            )
            short_desc = ""
        else:
            # Extract the short description from the Dockerfile_latest
            short_desc = ""
            with open(dockerfile_latest, "r") as f:
                for line in f:
                    if "org.opencontainers.image.description=" in line:
                        if '"' in line:
                            short_desc = line.split('"')[1]
                        elif "'" in line:
                            short_desc = line.split("'")[1]
                        break

        if not full_desc and not short_desc:
            logger.info(f"No descriptions found for {repo_name}, skipping")
            continue

        # Create payload for DockerHub API
        payload = {}
        if full_desc:
            payload["full_description"] = full_desc
        if short_desc:
            payload["description"] = short_desc

        # Update the DockerHub repository description
        headers = {"Content-Type": "application/json", "Authorization": f"JWT {token}"}

        response = requests.patch(
            f"https://hub.docker.com/v2/repositories/getwilds/{repo_name}/",
            headers=headers,
            json=payload,
        )

        if response.status_code != 200:
            logger.error(f"Error updating {repo_name}: {response.text}")
        else:
            logger.info(f"Successfully updated description for getwilds/{repo_name}")


def main():
    """Main function to orchestrate the Docker update process."""
    # Get the specified directory from command line argument if provided
    specified_dir = sys.argv[1] if len(sys.argv) > 1 else None

    # Find changed files
    docker_files, readme_files, affected_dirs = find_changed_files(specified_dir)

    # Build, push Docker images, and generate vulnerability reports
    if docker_files:
        build_and_push_images(docker_files)

    # Update DockerHub repository descriptions
    if affected_dirs:
        update_dockerhub_descriptions(affected_dirs)


if __name__ == "__main__":
    main()
