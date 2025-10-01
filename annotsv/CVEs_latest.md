# Vulnerability Report for getwilds/annotsv:latest

Report generated on 2025-10-01 08:58:40 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 22 |
| 🟠 High | 102 |
| 🟡 Medium | 81 |
| 🟢 Low | 31 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 11 |
| 🟢 Low | 14 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/annotsv:latest  │   22C   102H    81M    31L   
    digest             │  8c5f7fd63d55                     │                              
  Base image           │  ubuntu:22.04                     │    0C     0H    11M    14L   
  Refreshed base image │  ubuntu:22.04                     │    0C     0H     4M    13L   
                       │                                   │                  -7     -1   
  Updated base image   │  ubuntu:24.04                     │    0C     0H     5M     6L   
                       │                                   │                  -6     -8   

What's next:
    View vulnerabilities → docker scout cves getwilds/annotsv:latest
    View base image update recommendations → docker scout recommendations getwilds/annotsv:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/annotsv:latest --org <organization>
```
</details>
