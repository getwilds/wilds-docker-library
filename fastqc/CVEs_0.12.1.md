# Vulnerability Report for getwilds/fastqc:0.12.1

Report generated on 2025-11-01 08:37:01 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 13 |
| 🟢 Low | 14 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 5 |
| 🟢 Low | 6 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/fastqc:0.12.1  │    0C     0H    13M    14L   
    digest             │  bed0f17633b7                    │                              
  Base image           │  ubuntu:24.04                    │    0C     0H     5M     6L   
  Refreshed base image │  ubuntu:24.04                    │    0C     0H     2M     5L   
                       │                                  │                  -3     -1   
  Updated base image   │  ubuntu:25.04                    │    0C     0H     2M     4L   
                       │                                  │                  -3     -2   

What's next:
    View vulnerabilities → docker scout cves getwilds/fastqc:0.12.1
    View base image update recommendations → docker scout recommendations getwilds/fastqc:0.12.1
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/fastqc:0.12.1 --org <organization>
```
</details>
