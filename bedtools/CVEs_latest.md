# Vulnerability Report for getwilds/bedtools:latest

Report generated on 2025-11-01 09:42:04 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 14 |
| 🟡 Medium | 1448 |
| 🟢 Low | 42 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 13 |
| 🟢 Low | 6 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/bedtools:latest  │    0C    14H   1448M    42L   
    digest             │  24516c43b5f8                      │                               
  Base image           │  ubuntu:24.04                      │    0C     0H    13M     6L    
  Refreshed base image │  ubuntu:24.04                      │    0C     0H     2M     5L    
                       │                                    │                 -11     -1    
  Updated base image   │  ubuntu:25.04                      │    0C     0H     2M     4L    
                       │                                    │                 -11     -2    

What's next:
    View vulnerabilities → docker scout cves getwilds/bedtools:latest
    View base image update recommendations → docker scout recommendations getwilds/bedtools:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bedtools:latest --org <organization>
```
</details>
