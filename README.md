# wilds-docker-library

[![Project Status: Prototype – Useable, some support, open to feedback, unstable API.](https://getwilds.github.io/badges/badges/prototype.svg)](https://getwilds.org/badges/#prototype)

This repository is intended to be a central storage for all Docker images associated with WILDS. Normally, repositories are relatively self-contained and only need one image that can just be directly linked to that repository. However, WDL pipelines often require a different image for each step, creating the need for a laundry list of Docker images for each repository. In addition, our bioinformatics workflows will have a large amount of image overlap in that the same tools get used, just in a different fashion depending on the workflow. To avoid unnecessary image duplication, this repository will contain all Dockerfiles and images relevant to WILDS and all future workflows refer back to these images.

## Usage

```
docker pull ghcr.io/getwilds/IMAGENAME:VERSIONTAG
apptainer pull docker://ghcr.io/getwilds/IMAGENAME:VERSIONTAG
```

## Support

For questions, bugs, and/or feature requests, reach out to the Fred Hutch Data Science Lab (DaSL) at wilds@fredhutch.org, or open an issue on our [issue tracker](https://github.com/getwilds/wilds-docker-library/issues).

## Contributing Guidelines

- Because these Docker images will be used for individual steps within WDL workflows, they should be as minimal as possible in terms of the number of tools installed in each image (1 or 2 max).
- As a general (but flexible) rule, try to start from as basic of a parent image as possible, e.g. `scratch`, `ubuntu`, `python`, `r-base`, etc. Outside parent images are fine, as long as they are from a VERY trusted source, e.g. Ubuntu, Python, Conda, Rocker, etc.
- To speed up build and deployment of containers, try to keep image sizes relatively small (a few hundred MB on average, 2GB max). For that reason, reference data should not be stored in an image unless absolutely necessary.
- Every Dockerfile must contain the labels below at a minimum. This provides users with increased visibility in terms of where the image came from and open access to the necessary resources in case they have any questions or concerns.
```
LABEL org.opencontainers.image.title="awesomeimage" # Name of the image in question
LABEL org.opencontainers.image.description="Short description of awesomeimage and its purpose"
LABEL org.opencontainers.image.version="1.0" # Version tag of the image
LABEL org.opencontainers.image.authors="johndoe@fredhutch.org" # Author email address
LABEL org.opencontainers.image.url=https://hutchdatascience.org/ # Home page
LABEL org.opencontainers.image.documentation=https://getwilds.org/ # Documentation page
LABEL org.opencontainers.image.source=https://github.com/getwilds/wilds-docker-library # GitHub repo to link with
LABEL org.opencontainers.image.licenses=MIT # License type for the image in question
```
- When creating a different version of an existing image, use one of the other Dockerfiles as a starting template and modify it as needed. This will help to ensure that the only thing that has changed between image versions is the version of tool in question, not any strange formatting/configuration issues.
- Try to be as specific as possible in terms of tool versions within the Dockerfile, especially the parent image.
    - If you just specify "latest", a tag that get updated frequently over time, your image could be completely different the next time you build it, even though it uses the exact same Dockerfile.
    - On the other hand, specifying "v1.2.3" will always pull the same instance of the tool every time, providing greater reproducibility over time.
- In terms of the repo organization, each image should have its own directory named after the tool being used in the image. Each version of the image should have its own Dockerfile in that directory following the naming convention of `[IMAGENAME]/Dockerfile_[VERSIONTAG]`.
    - If formatted correctly, a GitHub Action will automatically build and upload the image to the [WILDS GitHub container registry](https://github.com/orgs/getwilds/packages) upon merging into the `main` branch.
- Before pushing the image to the WILDS package registry, try uploading it to your user-specific package registry using the command below and make sure it works for the WDL task in question.
```
docker build --platform linux/amd64 -t ghcr.io/GITHUBUSERNAME/IMAGENAME:VERSIONTAG -f IMAGENAME/Dockerfile_VERSIONTAG --push .
```

## License

Distributed under the MIT License. See `LICENSE` for details.

