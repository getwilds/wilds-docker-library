# Vulnerability Report for getwilds/scanpy:latest

Report generated on 2025-10-07 16:34:26 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |
| 🟡 Medium | 2 |
| 🟢 Low | 22 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |
| 🟡 Medium | 2 |
| 🟢 Low | 22 |

## 🔄 Recommendations

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/scanpy:latest-amd64  │    0C     1H     2M    22L   
    digest           │  7f1fc1deecc3                          │                              
  Base image         │  python:3.12-slim                      │    0C     1H     2M    22L   
  Updated base image │  python:3.13-slim                      │    0C     1H     2M    22L   
                     │                                        │                              

What's next:
    View vulnerabilities → docker scout cves getwilds/scanpy:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/scanpy:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/scanpy:latest-amd64 --org <organization>
```
</details>
