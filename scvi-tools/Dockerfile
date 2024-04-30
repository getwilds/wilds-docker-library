FROM python:3.10-slim

# Adding labels for the GitHub Container Registry
LABEL org.opencontainers.image.title="scvi-tools"
LABEL org.opencontainers.image.description="Container image for the use of scvi-tools library for Single-Cell analysis in Python"
LABEL org.opencontainers.image.version="latest"
LABEL org.opencontainers.image.authors="wilds@fredhutch.org"
LABEL org.opencontainers.image.url=https://hutchdatascience.org/
LABEL org.opencontainers.image.documentation=https://getwilds.org/
LABEL org.opencontainers.image.source=https://github.com/getwilds/wilds-docker-library
LABEL org.opencontainers.image.licenses=MIT

# Installing necessary libraries via pip
RUN pip install pandas==2.2.2 matplotlib==3.8.4 scanpy==1.10.1 leidenalg==0.10.2 torch==2.2.2 torchvision==0.17.2 \ 
				torchaudio==2.2 pytorch-cuda==12.1 jaxlib==0.4.26 jax==0.4.26  scikit-misc==0.3.1 scvi-tools==1.1.2
