# awscli

This directory contains Docker images for AWS CLI, the unified command-line interface for Amazon Web Services.

## Available Versions

- `latest` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/awscli/Dockerfile_latest) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/awscli/CVEs_latest.md) )
- `2.27.49` ( [Dockerfile](https://github.com/getwilds/wilds-docker-library/blob/main/awscli/Dockerfile_2.27.49) | [Vulnerability Report](https://github.com/getwilds/wilds-docker-library/blob/main/awscli/CVEs_2.27.49.md) )

## Image Details

These Docker images are built from Ubuntu Noble (24.04 LTS) base image and include:

- AWS CLI v2.27.49 (pinned version) or latest: Command-line interface for Amazon Web Services
- AWS Signing Helper v1.2.0: Certificate-based authentication helper for AWS IAM Roles Anywhere
- samtools v1.19.2: For BAM/SAM file manipulation and filtering
- curl: For downloading AWS CLI installer
- unzip: For extracting AWS CLI installer
- ca-certificates: For secure HTTPS connections

The images are designed to be minimal and focused on providing AWS CLI functionality for accessing **public cloud datasets**, with additional samtools support for BAM file processing. The inclusion of AWS Signing Helper enables certificate-based authentication for more secure access to private AWS resources when needed.

## Usage

### Docker

```bash
docker pull getwilds/awscli:latest
# or
docker pull getwilds/awscli:2.27.49

# Alternatively, pull from GitHub Container Registry
docker pull ghcr.io/getwilds/awscli:latest
```

### Singularity/Apptainer

```bash
apptainer pull docker://getwilds/awscli:latest
# or
apptainer pull docker://getwilds/awscli:2.27.49

# Alternatively, pull from GitHub Container Registry
apptainer pull docker://ghcr.io/getwilds/awscli:latest
```

## Authentication Methods

This image now supports multiple authentication methods:

### 1. Public Data Access (No Authentication)

**Recommended for most bioinformatics workflows**
```bash
# Download public data (no AWS credentials required)
docker run --rm -v /path/to/data:/data getwilds/awscli:latest \
  aws s3 sync --no-sign-request s3://gatk-test-data/wgs_bam/NA12878_20k_b37/ /data/
```

### 2. Certificate-Based Authentication (IAM Roles Anywhere)

For secure access to private AWS resources using x.509 certificates:

```bash
# Mount certificates and configure AWS CLI to use signing helper
docker run --rm \
  -v /path/to/certs:/certs:ro \
  -v /path/to/data:/data \
  -e AWS_PROFILE=roles-anywhere \
  getwilds/awscli:latest \
  aws s3 ls s3://private-bucket/
```

Example AWS CLI configuration for certificate authentication:
```ini
# ~/.aws/config
[profile roles-anywhere]
credential_process = aws_signing_helper credential-process \
  --certificate /certs/client.crt \
  --private-key /certs/client.key \
  --trust-anchor-arn arn:aws:rolesanywhere:region:account:trust-anchor/ta-id \
  --profile-arn arn:aws:rolesanywhere:region:account:profile/profile-id \
  --role-arn arn:aws:iam::account:role/role-name
```

### 3. Traditional IAM Credentials (Not Recommended for Containers)

If you must use traditional AWS credentials, mount them carefully:
```bash
# Use with caution - not recommended for production
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v /path/to/data:/data \
  getwilds/awscli:latest \
  aws s3 ls s3://private-bucket/
```

### Example Commands (Public Data Focus)

**Recommended: Public Data Access (No Credentials Required)**
```bash
# Download public data (no AWS credentials required)
docker run --rm -v /path/to/data:/data getwilds/awscli:latest \
  aws s3 sync --no-sign-request s3://gatk-test-data/wgs_bam/NA12878_20k_b37/ /data/

# List contents of a public S3 bucket
docker run --rm getwilds/awscli:latest \
  aws s3 ls --no-sign-request s3://gatk-test-data/

# Copy specific files from public bucket
docker run --rm -v /path/to/data:/data getwilds/awscli:latest \
  aws s3 cp --no-sign-request s3://gatk-test-data/wgs_bam/NA12878_20k_b37/NA12878.bam /data/

# Using Apptainer for public data
apptainer run --bind /path/to/data:/data docker://getwilds/awscli:latest \
  aws s3 sync --no-sign-request s3://gatk-test-data/wgs_bam/NA12878_20k_b37/ /data/
```

### Common Use Cases in Bioinformatics

**Download GATK Test Data:**
```bash
# Get small test BAM files (< 1GB)
docker run --rm -v $(pwd):/data getwilds/awscli:latest \
  aws s3 sync --no-sign-request s3://gatk-test-data/wgs_bam/NA12878_20k_b37/ /data/test-bams/
```

**Download and Filter BAM Files:**
```bash
# Download test BAM and subset to chromosome 1 only
docker run --rm -v $(pwd):/data getwilds/awscli:latest bash -c "
  aws s3 cp --no-sign-request s3://gatk-test-data/wgs_bam/NA12878_20k_b37/NA12878.bam /data/ &&
  samtools view -b /data/NA12878.bam chr1 > /data/NA12878_chr1.bam &&
  samtools index /data/NA12878_chr1.bam
"

# Create an even smaller test file with first 1000 reads
docker run --rm -v $(pwd):/data getwilds/awscli:latest bash -c "
  aws s3 cp --no-sign-request s3://gatk-test-data/wgs_bam/NA12878_20k_b37/NA12878.bam /data/ &&
  samtools view -b /data/NA12878.bam | head -n 1000 | samtools view -b > /data/NA12878_1k.bam
"
```

**Download Reference Genomes:**
```bash
# Download reference files from public buckets
docker run --rm -v $(pwd):/data getwilds/awscli:latest \
  aws s3 cp --no-sign-request s3://broad-references/hg38/v0/Homo_sapiens_assembly38.fasta /data/
```

**Batch Download ENCODE Data:**
```bash
# Download multiple files with filtering
docker run --rm -v $(pwd):/data getwilds/awscli:latest \
  aws s3 sync --no-sign-request s3://encode-public/2020/01/01/ /data/ --exclude "*" --include "*.bam"
```

**BAM File Quality Control:**
```bash
# Download and check BAM file statistics
docker run --rm -v $(pwd):/data getwilds/awscli:latest bash -c "
  aws s3 cp --no-sign-request s3://gatk-test-data/wgs_bam/NA12878_20k_b37/NA12878.bam /data/ &&
  samtools flagstat /data/NA12878.bam > /data/NA12878_stats.txt &&
  samtools idxstats /data/NA12878.bam > /data/NA12878_idxstats.txt
"
```

## Security Features

The AWS CLI Docker images include:

- Pinned package versions for reproducibility
- Minimal package installation to reduce attack surface
- Use of `--no-install-recommends` to minimize dependencies
- Proper cleanup of package caches and temporary files
- **Support for certificate-based authentication** - more secure than traditional access keys
- **Optimized for public data access** - no credential management required for most use cases

### Security Recommendations

**Recommended: Public Data Only**
- Use this image primarily for downloading public datasets (GATK test data, reference genomes, ENCODE data, etc.)
- Always use the `--no-sign-request` flag for public S3 buckets
- No AWS credentials needed - safer and simpler

**Acceptable: Certificate-Based Authentication**
- Use AWS IAM Roles Anywhere with x.509 certificates for private data access
- Certificates provide better security than long-lived access keys
- Mount certificates as read-only volumes
- Consider using temporary certificates when possible

**Not Recommended: Traditional IAM Credentials**
- Avoid mounting AWS credentials (`~/.aws`) into containers when possible
- If you must use traditional credentials, ensure proper file permissions and use read-only mounts
- Consider using AWS IAM roles for service accounts (IRSA) in Kubernetes environments instead

### Security Scanning and CVEs

These images are regularly scanned for vulnerabilities using Docker Scout. However, due to the nature of bioinformatics software and their dependencies, some Docker images may contain components with known vulnerabilities (CVEs).

**Use at your own risk**: While we strive to minimize security issues, these images are primarily designed for research and analytical workflows in controlled environments.

For the latest security information about this image, please check the `CVEs_*.md` files in this directory, which are automatically updated through our GitHub Actions workflow. If a particular vulnerability is of concern, please file an [issue](https://github.com/getwilds/wilds-docker-library/issues) in the GitHub repo citing which CVE you would like to be addressed.

## Configuration

### Public Data Access (Recommended)

For public datasets, no configuration is required. Simply use the `--no-sign-request` flag:
```bash
aws s3 [command] --no-sign-request s3://public-bucket/path/
```

**Popular Public Bioinformatics Datasets:**
- `s3://gatk-test-data/` - GATK test datasets
- `s3://broad-references/` - Reference genomes
- `s3://encode-public/` - ENCODE consortium data
- `s3://1000genomes/` - 1000 Genomes Project data

### Certificate-Based Authentication Setup

To use AWS IAM Roles Anywhere with certificates:

1. **Set up IAM Roles Anywhere** in your AWS account
2. **Create a trust anchor** with your Certificate Authority
3. **Create a profile** that maps certificates to IAM roles
4. **Configure AWS CLI** to use the signing helper:

```bash
# Create AWS config file
mkdir -p ~/.aws
cat > ~/.aws/config << EOF
[profile roles-anywhere]
credential_process = aws_signing_helper credential-process \\
  --certificate /path/to/client.crt \\
  --private-key /path/to/client.key \\
  --trust-anchor-arn arn:aws:rolesanywhere:region:account:trust-anchor/ta-id \\
  --profile-arn arn:aws:rolesanywhere:region:account:profile/profile-id \\
  --role-arn arn:aws:iam::account:role/role-name
EOF
```

5. **Use the profile** with the container:
```bash
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v /path/to/certs:/certs:ro \
  -e AWS_PROFILE=roles-anywhere \
  getwilds/awscli:latest \
  aws s3 ls
```

## Dockerfile Structure

The Dockerfile follows these main steps:

1. Uses Ubuntu Noble (24.04 LTS) as the base image
2. Adds metadata labels for documentation and attribution
3. Sets shell options for robust error handling (`pipefail`)
4. Dynamically determines and pins package versions for reproducibility
5. Installs AWS CLI v2 from official AWS distribution
6. Installs AWS Signing Helper from official AWS Roles Anywhere releases
7. Cleans up installation artifacts to minimize image size

## Source Repository

These Dockerfiles are maintained in the [WILDS Docker Library](https://github.com/getwilds/wilds-docker-library) repository.
