#!/usr/bin/env python
# -*-coding:utf-8 -*-
"""
@File    :   docker_scout.py
@Time    :   2025/04/17 12:54:33
@Author  :   Taylor Firman
@Version :   v0.1
@Contact :   tfirman@fredhutch.org
@Desc    :   This script automates the process of scanning Docker images for vulnerabilities
using Docker Scout. It handles discovering tools and tags, scanning each image,
and committing the resulting CVE reports.

Usage:
    python docker_scout.py [tool_name]

    If tool_name is provided, only that tool will be scanned.
    If no tool_name is provided, all tools will be scanned.

Environment variables:
    GITHUB_REF_NAME: The branch or ref name
    GITHUB_EVENT_NAME: The name of the GitHub event that triggered the workflow
    GITHUB_HEAD_REF: The branch being merged from in case of PR's
"""

import os
import sys
import glob
import logging
from datetime import datetime
import git
from utils import run_command

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("docker-scout")


def discover_tools_and_tags(specific_tool=None):
    """
    Discover all tools and their tags from Dockerfile_* files.

    Args:
        specific_tool: If provided, only discover tags for this tool

    Returns:
        List of (tool, tag) tuples
    """
    tool_tags = []

    # Determine which directories to process
    if specific_tool:
        if not os.path.isdir(specific_tool):
            logger.error(f"Error: Directory '{specific_tool}' does not exist.")
            sys.exit(1)
        dirs = [specific_tool]
        logger.info(f"Processing single tool: {specific_tool}")
    else:
        # Get all directories except .git and .github
        dirs = [
            d
            for d in glob.glob("*")
            if os.path.isdir(d) and d not in [".git", ".github"]
        ]
        logger.info(f"Processing all tool directories: {dirs}")

    # Find all Dockerfile_* files to determine tags
    for tool_dir in dirs:
        dockerfiles = glob.glob(f"{tool_dir}/Dockerfile_*")

        if not dockerfiles:
            logger.info(f"No Dockerfile_* files found in {tool_dir}")
            continue

        for dockerfile in dockerfiles:
            # Extract tag from filename (everything after the underscore)
            tag = os.path.basename(dockerfile).split("_")[-1]
            tool_tags.append((tool_dir, tag))
            logger.info(f"Found {tool_dir}:{tag}")

    return tool_tags


def scan_image(tool, tag):
    """
    Scan a Docker image with Docker Scout and generate CVE report.

    Args:
        tool: The tool name
        tag: The image tag

    Returns:
        Path to the generated CVE report file
    """
    container = f"ghcr.io/getwilds/{tool}:{tag}"
    cve_file = f"{tool}/CVEs_{tag}.md"

    logger.info(f"Scanning {container}...")

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(cve_file), exist_ok=True)

    # Generate header for the file
    with open(cve_file, "w") as f:
        pst_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S PST")
        f.write(f"# Vulnerability Report for {container}\n\n")
        f.write(f"Report generated on {pst_now}\n\n")

    # Run Docker Scout to generate CVE report
    result = run_command(
        f"docker scout cves {container} --format markdown --only-fixed", capture_output=True
    )

    with open(cve_file, "a") as f:
        f.write(result)

    # Replace ghcr.io/getwilds with getwilds in the report
    with open(cve_file, "r") as f:
        content = f.read()

    with open(cve_file, "w") as f:
        f.write(content.replace("ghcr.io/getwilds/", "getwilds/"))

    logger.info(f"Created vulnerability report at {cve_file}")

    # Clean up Docker images to save space
    run_command("docker system prune -af", check=False)

    return cve_file


def commit_changes(cve_files):
    """
    Commit and push CVE report files to the repository.

    Args:
        cve_files: List of CVE report files to commit
    """
    if not cve_files:
        logger.info("No CVE files to commit")
        return

    repo = git.Repo(".")

    # Configure Git
    repo.git.config("--global", "user.name", "WILDS Docker Library Automation[bot]")
    repo.git.config(
        "--global", "user.email", "github-actions[bot]@users.noreply.github.com"
    )

    # Determine which branch to use
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    ref_name = os.environ.get("GITHUB_REF_NAME", "main")

    if event_name == "pull_request":
        # For pull requests, identify name of the source branch
        head_ref = os.environ.get("GITHUB_HEAD_REF", "")
        if head_ref:
            logger.info(f"Pull request detected, source branch: {head_ref}")
            repo.git.fetch("origin", head_ref)
            repo.git.checkout(head_ref)
            ref_name = head_ref
        else:
            logger.error("Pull request detected but GITHUB_HEAD_REF not found")
            return
    else:
        # For direct branch pushes or workflow_dispatch
        logger.info(f"Working with branch {ref_name}")

    # Check if there are changes to commit
    if repo.is_dirty(untracked_files=True):
        # Stage CVE files
        for cve_file in cve_files:
            repo.git.add(cve_file)

        # Commit changes
        repo.git.commit("-m", "Update vulnerability reports [skip ci]")

        # Push changes
        logger.info(f"Pushing changes to {ref_name}")
        try:
            token = os.environ.get("GH_APP_TOKEN")
            repo.git.push(
                f"https://x-access-token:{token}@github.com/getwilds/wilds-docker-library.git",
                ref_name,
            )
            logger.info("Successfully pushed changes")
        except git.GitCommandError as e:
            logger.error(f"Failed to push changes: {e}")
    else:
        logger.info("No changes to commit")


def main():
    """Main function to orchestrate the Docker Scout analysis."""
    # Get the specific tool from command line argument if provided
    specific_tool = sys.argv[1] if len(sys.argv) > 1 else None

    # Discover tools and tags
    tool_tags = discover_tools_and_tags(specific_tool)

    if not tool_tags:
        logger.warning("No tools or tags found to scan.")
        return

    logger.info(f"Found {len(tool_tags)} tool/tag combinations to scan")

    # Scan each tool/tag combination and collect CVE files
    cve_files = []
    for tool, tag in tool_tags:
        cve_file = scan_image(tool, tag)
        cve_files.append(cve_file)

    # Commit and push changes
    commit_changes(cve_files)


if __name__ == "__main__":
    main()
