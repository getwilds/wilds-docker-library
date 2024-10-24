#!/bin/bash

# Script to check API calls to GitHub and Pip packages and return list with existing version of Dockerimages

get_current_version() {
    local DOCKER=$1

    VERSIONED_FILES=$(find "../${DOCKER}" -maxdepth 1 -type f -name 'Dockerfile_*' | grep -v 'Dockerfile_latest')
    CURRENT_VERSION_FILE=$(echo "$VERSIONED_FILES" | grep -Eo 'Dockerfile_[0-9]+\.[0-9]+' | sort -V | tail -n 1)
    
    if [ -z "$CURRENT_VERSION_FILE" ]; then
        echo "No versioned Dockerfile found for ${DOCKER}."
        return 1
    fi
    
    CURRENT_VERSION=$(echo "$CURRENT_VERSION_FILE" | grep -Eo '[0-9]+\.[0-9]+')
    echo "$CURRENT_VERSION"
}


## Tools with Github API calls
declare -A github_dict=(["samtools"]="samtools/samtools" ["bedtools"]="arq5x/bedtools2" ["bcftools"]="samtools/bcftools" ["bwa"]="lh3/bwa" ["picard"]="broadinstitute/picard" \
                        ["star"]="alexdobin/STAR" ["umitools"]="CGATOxford/UMI-tools" ["rtorch"]="mlverse/torch")

for DOCKER in "${!github_dict[@]}"
do
    LATEST_VERSION=$(curl --silent "https://api.github.com/repos/${github_dict[$DOCKER]}/releases/latest" | jq -r .tag_name)
    CURRENT_VERSION=$(get_current_version "$DOCKER")
    echo "${DOCKER}:${CURRENT_VERSION}:${LATEST_VERSION}" >> version_list.txt
done

## Tools with PyPi API calls
declare -A pypi_dict=(["scanpy"]="scanpy" ["scvi-tools"]="scvi-tools")
for DOCKER in "${!pypi_dict[@]}"
do
    LATEST_VERSION=$(curl --silent "https://pypi.org/pypi/${pypi_dict[$DOCKER]}/json" | jq -r '.info.version')
    CURRENT_VERSION=$(get_current_version "$DOCKER")
    echo "${DOCKER}:${CURRENT_VERSION}:${LATEST_VERSION}" >> version_list.txt
done

## GATK
LATEST_VERSION=$(curl --silent "https://api.anaconda.org/package/bioconda/gatk4" | jq -r '.latest_version')
CURRENT_VERSION=$(get_current_version "gatk")
echo "gatk:${CURRENT_VERSION}:${LATEST_VERSION}" >> version_list.txt

# ## sra-tools
# TOOL="sra-tools"
# LATEST_VERSION=$(curl --silent "https://api.github.com/repos/ncbi/${TOOL}/tags" | jq -r '.[0].name')
# CURRENT_VERSION=$(get_current_version "$TOOL")
# echo "${TOOL}:${CURRENT_VERSION}:${LATEST_VERSION}" >> version_list.txt

{ echo Tool:Current_version: Latest_version; cat version_list.txt; } | csvlook

rm version_list.txt