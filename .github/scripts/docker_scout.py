#!/usr/bin/env python
# -*-coding:utf-8 -*-
"""
@File    :   docker_scout.py
@Time    :   2025/04/17 12:54:33
@Author  :   Taylor Firman
@Version :   v0.1
@Contact :   tfirman@fredhutch.org
@Desc    :   This script automates the process of scanning Docker images for vulnerabilities
using Docker Scout. It handles discovering tools and tags and scanning each image.

Usage:
    python docker_scout.py [tool_name]

    If tool_name is provided, only that tool will be scanned.
    If no tool_name is provided, all tools will be scanned.
    Generates CVE reports in markdown format for each tool and tag combination.
    Passes along the CVE report files to the commit step via .cve_manifest.txt.
"""

import os
import sys
import glob
import logging
import time
from datetime import datetime
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

    if os.path.exists('.cve_manifest.txt'):
        logger.info("Found existing .cve_manifest.txt, excluding tools already scanned")
        with open('.cve_manifest.txt', 'r') as f:
            existing_scans = [line.strip() for line in f if line.strip()]
    else:
        existing_scans = []

    # Find all Dockerfile_* files to determine tags
    for tool_dir in dirs:
        dockerfiles = glob.glob(f"{tool_dir}/Dockerfile_*")

        if not dockerfiles:
            logger.info(f"No Dockerfile_* files found in {tool_dir}")
            continue

        for dockerfile in dockerfiles:
            # Extract tag from filename (everything after the underscore)
            tag = os.path.basename(dockerfile).split("_")[-1]
            cve_file = f"{tool_dir}/CVEs_{tag}.md"
            if cve_file in existing_scans:
                logger.info(f"Skipping {tool_dir}:{tag} - already scanned")
                continue
            else:
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

    try:
        # Run Docker Scout to generate CVE report
        result = run_command(
            f"docker scout quickview {container} --format markdown", capture_output=True
        )

        with open(cve_file, "w") as f:
            pst_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S PST")
            f.write(f"# Vulnerability Report for {container}\n\n")
            f.write(f"Report generated on {pst_now}\n\n")
            f.write(result)
        
        # Replace ghcr.io/getwilds with getwilds in the report
        with open(cve_file, "r") as f:
            content = f.read()
        with open(cve_file, "w") as f:
            f.write(content.replace("ghcr.io/getwilds/", "getwilds/"))
        
        logger.info(f"Successfully generated CVE report for {container}")
    except Exception as e:
        logger.warning(f"Docker Scout failed for {container}: {e}")
        cve_file = None

    # Clean up Docker images to save space
    time.sleep(10)  # Let Docker Scout fully complete
    run_command("find /tmp -name 'docker-scout*' -o -name 'stereoscope-*' 2>/dev/null | xargs rm -rf", check=False)
    run_command("docker system prune -af --volumes", check=False)
    run_command("docker builder prune -af", check=False)

    return cve_file


def main():
    """Generate CVE reports and write manifest of successful scans."""
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
        if cve_file is not None:  # Only add successful scans
            cve_files.append(cve_file)

    # Write manifest of successful CVE files for commit step
    with open('.cve_manifest.txt', 'a') as f:
        for cve_file in cve_files:
            f.write(f"{cve_file}\n")
    
    logger.info(f"Generated {len(cve_files)} CVE reports")

if __name__ == "__main__":
    main()
