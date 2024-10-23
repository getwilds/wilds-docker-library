#!/bin/bash

# Script to check API calls to GitHub and Pip packages

SAMTOOLS_REPO="samtools/samtools"
LATEST_VERSION=$(curl --silent "https://api.github.com/repos/${SAMTOOLS_REPO}/releases/latest" | jq -r .tag_name)
echo "Latest version of Samtools is ${LATEST_VERSION}"

bedtools_repo="arq5x/bedtools2"
LATEST_VERSION=$(curl --silent "https://api.github.com/repos/${bedtools_repo}/releases/latest" | jq -r .tag_name)
echo "Latest version of BEDtools is ${LATEST_VERSION}"

bcftools_repo="samtools/bcftools"
LATEST_VERSION=$(curl --silent "https://api.github.com/repos/${bcftools_repo}/releases/latest" | jq -r .tag_name)
echo "Latest version of bcftools is ${LATEST_VERSION}"

bwa_repo="lh3/bwa"
LATEST_VERSION=$(curl --silent "https://api.github.com/repos/${bwa_repo}/releases/latest" | jq -r .tag_name)
echo "Latest version of BWA is ${LATEST_VERSION}"

PICARD_REPO="broadinstitute/picard"
LATEST_VERSION=$(curl --silent "https://api.github.com/repos/${PICARD_REPO}/releases/latest" | jq -r .tag_name)
echo "Latest version of Picard is ${LATEST_VERSION}"

star_repo="alexdobin/STAR"
LATEST_VERSION=$(curl --silent "https://api.github.com/repos/${star_repo}/releases/latest" | jq -r .tag_name)
echo "Latest version of STAR is ${LATEST_VERSION}"

umiTools_repo="CGATOxford/UMI-tools"
LATEST_VERSION=$(curl --silent "https://api.github.com/repos/${umiTools_repo}/releases/latest" | jq -r .tag_name)
echo "Latest version of UMI-Tools is ${LATEST_VERSION}"

SRATOOLS_REPO="ncbi/sra-tools"
LATEST_VERSION=$(curl --silent "https://api.github.com/repos/${SRATOOLS_REPO}/tags" | jq -r '.[0].name')
echo "Latest version of sra-tools is ${LATEST_VERSION}"

rTorch_REPO="mlverse/torch"
LATEST_VERSION=$(curl --silent "https://api.github.com/repos/${rTorch_REPO}/releases/latest" | jq -r .tag_name)
echo "Latest version of R-Torch is ${LATEST_VERSION}"

scanpy_version=$(curl --silent "https://pypi.org/pypi/scanpy/json" | jq -r '.info.version')
echo "Latest version of Scanpy is ${scanpy_version}"

scvitools_version=$(curl --silent "https://pypi.org/pypi/scvi-tools/json" | jq -r '.info.version')
echo "Latest version of scvi-tools is ${scvitools_version}"

gatk4_version=$(curl --silent "https://api.anaconda.org/package/bioconda/gatk4" | jq -r '.latest_version')
echo "Latest version of GATK4 is ${gatk4_version}"


