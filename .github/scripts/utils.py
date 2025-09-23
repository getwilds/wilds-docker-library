#!/usr/bin/env python
# -*-coding:utf-8 -*-
"""
@File    :   utils.py
@Time    :   2025/04/22 10:02:00
@Author  :   Taylor Firman
@Version :   v0.1
@Contact :   tfirman@fredhutch.org
@Desc    :   Shared utility functions for Docker automation scripts
"""

import logging
import re
import subprocess

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("docker-utils")


def run_command(cmd, cwd=None, check=True, capture_output=False):
    """Run a shell command and return its output.

    Args:
        cmd: Command string to execute
        cwd: Current working directory for the command
        check: Whether to raise an exception if the command fails
        capture_output: Whether to capture and return command output

    Returns:
        If capture_output is True, returns the command output as string.
        Otherwise, returns True if the command succeeded.
    """
    logger.info(f"Running: {cmd}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=check,
            shell=True,
            text=True,
            capture_output=capture_output,
        )
        if capture_output:
            return result.stdout.strip()
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
        logger.error(f"Return code: {e.returncode}")
        if e.stdout:
            logger.error(f"STDOUT: {e.stdout}")
        if e.stderr:
            logger.error(f"STDERR: {e.stderr}")
        if check:
            raise
        return False


def parse_scout_quickview(scout_output):
    """
    Parse Docker Scout quickview output into a clean markdown format.

    Args:
        scout_output: Raw text output from docker scout quickview

    Returns:
        Formatted markdown string
    """
    lines = scout_output.strip().split("\n")

    # Initialize variables
    target_info = {}
    base_image_info = {}
    recommendations = []

    # Parse the output
    for line in lines:
        line = line.strip()

        # Parse target image line - extract image name and vulnerability counts
        if "│" in line and ("C" in line or "H" in line or "M" in line or "L" in line):
            parts = [p.strip() for p in line.split("│")]
            if len(parts) >= 3:
                # First part is the label (Target, Base image, etc.)
                label = parts[0].strip()
                image_name = parts[1].strip()
                vuln_counts = parts[2].strip()

                if label == "Target":
                    target_info["name"] = image_name
                    target_info["vulnerabilities"] = vuln_counts
                elif label == "Base image":
                    base_image_info["name"] = image_name
                    base_image_info["vulnerabilities"] = vuln_counts
                elif "base image" in label.lower():
                    # Handle refreshed/updated base image recommendations
                    recommendations.append(
                        {
                            "type": label,
                            "name": image_name,
                            "vulnerabilities": vuln_counts,
                        }
                    )

        # Parse digest line
        elif "digest" in line and "│" in line:
            parts = [p.strip() for p in line.split("│")]
            if len(parts) >= 2:
                target_info["digest"] = parts[1].strip()

    # Build markdown output
    markdown = ""

    # Target image summary
    if target_info:
        markdown += "## 📊 Vulnerability Summary\n\n"

        if "vulnerabilities" in target_info:
            # Parse vulnerability counts
            vuln_data = target_info["vulnerabilities"]

            # Extract counts using regex
            critical = re.search(r"(\d+)C", vuln_data)
            high = re.search(r"(\d+)H", vuln_data)
            medium = re.search(r"(\d+)M", vuln_data)
            low = re.search(r"(\d+)L", vuln_data)
            unknown = re.search(r"(\d+)\?", vuln_data)

            markdown += "| Severity | Count |\n"
            markdown += "|----------|-------|\n"
            markdown += f"| 🔴 Critical | {critical.group(1) if critical else '0'} |\n"
            markdown += f"| 🟠 High | {high.group(1) if high else '0'} |\n"
            markdown += f"| 🟡 Medium | {medium.group(1) if medium else '0'} |\n"
            markdown += f"| 🟢 Low | {low.group(1) if low else '0'} |\n"
            markdown += f"| ⚪ Unknown | {unknown.group(1) if unknown else '0'} |\n\n"

    # Base image info
    if base_image_info:
        markdown += "## 🐳 Base Image\n\n"
        markdown += f"**Image:** `{base_image_info['name']}`\n\n"

        if "vulnerabilities" in base_image_info:
            vuln_data = base_image_info["vulnerabilities"]
            critical = re.search(r"(\d+)C", vuln_data)
            high = re.search(r"(\d+)H", vuln_data)
            medium = re.search(r"(\d+)M", vuln_data)
            low = re.search(r"(\d+)L", vuln_data)

            markdown += "| Severity | Count |\n"
            markdown += "|----------|-------|\n"
            markdown += f"| 🔴 Critical | {critical.group(1) if critical else '0'} |\n"
            markdown += f"| 🟠 High | {high.group(1) if high else '0'} |\n"
            markdown += f"| 🟡 Medium | {medium.group(1) if medium else '0'} |\n"
            markdown += f"| 🟢 Low | {low.group(1) if low else '0'} |\n\n"

    # Recommendations
    if recommendations:
        markdown += "## 🔄 Recommendations\n\n"
        for rec in recommendations:
            markdown += f"**{rec['type']}:** `{rec['name']}`\n"
            if "vulnerabilities" in rec:
                vuln_data = rec["vulnerabilities"]
                # Parse improvement (negative numbers)
                critical_imp = re.search(r"(-?\d+)", vuln_data)
                if critical_imp and int(critical_imp.group(1)) < 0:
                    markdown += "- ✅ Reduces vulnerabilities\n"
            markdown += "\n"

    # Add raw output section for reference
    markdown += "<details>\n"
    markdown += "<summary>📋 Raw Docker Scout Output</summary>\n\n"
    markdown += "```text\n"
    markdown += scout_output
    markdown += "\n```\n"
    markdown += "</details>\n"

    return markdown
