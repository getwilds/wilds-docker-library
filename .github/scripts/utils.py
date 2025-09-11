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
