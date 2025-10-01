# Vulnerability Report for getwilds/scvi-tools:latest

Report generated on 2025-10-01 09:27:54 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 2 |
| 🟠 High | 1 |
| 🟡 Medium | 3 |
| 🟢 Low | 23 |
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

**Updated base image:** `python:3.13.7-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/scvi-tools:latest  │    2C     1H     3M    23L   
    digest           │  6a60922aa100                        │                              
  Base image         │  python:3.12-slim                    │    0C     1H     2M    22L   
  Updated base image │  python:3.13.7-slim                  │    0C     1H     2M    22L   
                     │                                      │                              

What's next:
    View vulnerabilities → docker scout cves getwilds/scvi-tools:latest
    View base image update recommendations → docker scout recommendations getwilds/scvi-tools:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/scvi-tools:latest --org <organization>
```
</details>
