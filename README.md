# wilds-docker-library

[![Project Status: Prototype – Useable, some support, open to feedback, unstable API.](https://getwilds.github.io/badges/badges/prototype.svg)](https://getwilds.org/badges/#prototype)

This repository is intended to be a central storage for all Docker containers associated with WILDS. Normally, repositories are relatively self-contained and only need one container that can just be directly linked to that repository. However, WDL pipelines often require a different container for each step, creating the need for a laundry list of Docker containers for each repository. In addition, our bioinformatics workflows will have a large amount of container overlap in that the same tools get used, just in a different fashion depending on the workflow. To avoid unnecessary container duplication, this repository will contain all Dockerfiles and containers relevant to WILDS and all future workflows refer back to these containers.

## Usage

```
docker pull ghcr.io/getwilds/CONTAINERNAME:VERSIONTAG
apptainer pull docker://ghcr.io/getwilds/CONTAINERNAME:VERSIONTAG
```

## Support

For questions, bugs, and/or feature requests, reach out to the Fred Hutch Data Science Lab (DaSL) at wilds@fredhutch.org, or open an issue on our [issue tracker](https://github.com/getwilds/wilds-docker-library/issues).

## Contributing

Still working on this protocol...

## License

Distributed under the MIT License. See `LICENSE` for details.

