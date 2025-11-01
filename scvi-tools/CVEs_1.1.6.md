# Vulnerability Report for getwilds/scvi-tools:1.1.6

Report generated on 2025-11-01 09:38:00 PST

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

**Refreshed base image:** `python:3.12-slim`

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/scvi-tools:1.1.6  │    2C     1H     3M    23L   
    digest             │  855e053a5265                       │                              
  Base image           │  python:3.12-slim                   │    0C     1H     2M    22L   
  Refreshed base image │  python:3.12-slim                   │    0C     0H     2M    20L   
                       │                                     │           -1            -2   
  Updated base image   │  python:3.13-slim                   │    0C     0H     2M    20L   
                       │                                     │           -1            -2   

What's next:
    View vulnerabilities → docker scout cves getwilds/scvi-tools:1.1.6
    View base image update recommendations → docker scout recommendations getwilds/scvi-tools:1.1.6
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/scvi-tools:1.1.6 --org <organization>
```
</details>
