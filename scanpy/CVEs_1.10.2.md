# Vulnerability Report for getwilds/scanpy:1.10.2

Report generated on 2025-11-01 08:50:34 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 12 |
| 🟢 Low | 15 |
| ⚪ Unknown | 1 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 12 |
| 🟢 Low | 15 |

## 🔄 Recommendations

**Refreshed base image:** `python:3.12-slim`

**Updated base image:** `python:3.14-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/scanpy:1.10.2  │    0C     5H    12M    15L     1?   
    digest             │  533ab8e4b699                    │                                     
  Base image           │  python:3.12-slim                │    0C     5H    12M    15L     1?   
  Refreshed base image │  python:3.12-slim                │    0C     0H     2M    20L          
                       │                                  │           -5    -10     +5     -1   
  Updated base image   │  python:3.14-slim                │    0C     0H     2M    20L          
                       │                                  │           -5    -10     +5     -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/scanpy:1.10.2
    View base image update recommendations → docker scout recommendations getwilds/scanpy:1.10.2
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/scanpy:1.10.2 --org <organization>
```
</details>
