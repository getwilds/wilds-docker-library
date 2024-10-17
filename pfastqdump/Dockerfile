
# Using the Miniconda base image
FROM condaforge/miniforge3:24.7.1-2

# Adding labels for the GitHub Container Registry
LABEL org.opencontainers.image.title="pfastqdump"
LABEL org.opencontainers.image.description="Container image for the use of parallel-fastq-dump in FH DaSL's WILDS"
LABEL org.opencontainers.image.version="0.6.7"
LABEL org.opencontainers.image.authors="wilds@fredhutch.org"
LABEL org.opencontainers.image.url=https://hutchdatascience.org/
LABEL org.opencontainers.image.documentation=https://getwilds.org/
LABEL org.opencontainers.image.source=https://github.com/getwilds/wilds-docker-library
LABEL org.opencontainers.image.licenses=MIT

# Switching from hard-links to copies and installing pfastqdump
RUN conda config --set always_copy true \
  && conda install -y -c bioconda parallel-fastq-dump=0.6.7 'sra-tools>=2.10.0'
