# Vulnerability Report for getwilds/scanpy:1.10.2

Report generated on 2025-10-01 08:49:42 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 4 |
| 🟡 Medium | 12 |
| 🟢 Low | 14 |
| ⚪ Unknown | 1 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 4 |
| 🟡 Medium | 12 |
| 🟢 Low | 14 |

## 🔄 Recommendations

**Refreshed base image:** `python:3.12-slim`

**Updated base image:** `python:3.13.7-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/scanpy:1.10.2  │    0C     4H    12M    14L     1?   
    digest             │  533ab8e4b699                    │                                     
  Base image           │  python:3.12-slim                │    0C     4H    12M    14L     1?   
  Refreshed base image │  python:3.12-slim                │    0C     1H     2M    22L          
                       │                                  │           -3    -10     +8     -1   
  Updated base image   │  python:3.13.7-slim              │    0C     1H     2M    22L          
                       │                                  │           -3    -10     +8     -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/scanpy:1.10.2
    View base image update recommendations → docker scout recommendations getwilds/scanpy:1.10.2
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/scanpy:1.10.2 --org <organization>
```
</details>
