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
import logging
import requests
from datetime import datetime
import git
from utils import run_command

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("docker-update")


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

    repo = git.Repo(".")

    # Configure Git
    repo.git.config("--global", "user.name", "WILDS Docker Library Automation[bot]")
    repo.git.config(
        "--global", "user.email", "github-actions[bot]@users.noreply.github.com"
    )

    cve_files = []

    for dockerfile in docker_files:
        if not os.path.isfile(dockerfile):
            logger.warning(f"File not found: {dockerfile}")
            continue

        # Extract tool name and tag from path
        tool_name = os.path.dirname(dockerfile)
        tag = os.path.basename(dockerfile).split("_")[-1]

        logger.info(f"Building image for {tool_name}:{tag}")

        # Build the image once
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

        with open(cve_file, "w") as f:
            pst_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S PST")
            f.write(f"# Vulnerability Report for getwilds/{tool_name}:{tag}\n\n")
            f.write(f"Report generated on {pst_now}\n\n")

        try:
            result = run_command(
                f"docker scout quickview ghcr.io/getwilds/{tool_name}:{tag} --format markdown",
                capture_output=True,
            )

            with open(cve_file, "a") as f:
                f.write(result)
            
            logger.info(f"Successfully generated CVE report for {tool_name}:{tag}")
        except Exception as e:
            logger.warning(f"Docker Scout failed for {tool_name}:{tag}: {e}")
            # Write a fallback message to the CVE file
            with open(cve_file, "a") as f:
                f.write(f"**Docker Scout scan failed for this image**\n\n")
                f.write(f"Error: {str(e)}\n\n")

        # Replace ghcr.io/getwilds with getwilds in the report
        with open(cve_file, "r") as f:
            content = f.read()

        with open(cve_file, "w") as f:
            f.write(content.replace("ghcr.io/getwilds/", "getwilds/"))

        logger.info(
            f"Successfully generated vulnerability report for getwilds/{tool_name}:{tag}"
        )

        # Add CVE file to git staging
        repo.git.add(cve_file)
        cve_files.append(cve_file)

        # Clean up Docker images to save space
        run_command("docker system prune -af", check=False)

    # Check if there are any staged changes to commit
    if not repo.git.diff("--staged"):
        logger.info("No changes to commit")
    else:
        # Commit and push CVE reports
        ref_name = os.environ.get("GITHUB_REF_NAME", "main")
        repo.git.commit("-m", "Update vulnerability reports [skip ci]")
        token = os.environ.get("GH_APP_TOKEN")
        repo.git.push(
            f"https://x-access-token:{token}@github.com/getwilds/wilds-docker-library.git",
            ref_name,
        )
        logger.info("Committed and pushed vulnerability reports")

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
