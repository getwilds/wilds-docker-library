# Vulnerability Report for getwilds/gtf-smash:latest

Report generated on 2025-11-01 08:33:37 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 21 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 20 |

## 🔄 Recommendations

**Refreshed base image:** `python:3.12-slim`

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/gtf-smash:latest  │    0C     0H     2M    21L   
    digest             │  91e5dc7f8138                       │                              
  Base image           │  python:3.12-slim                   │    0C     0H     2M    20L   
  Refreshed base image │  python:3.12-slim                   │    0C     0H     2M    20L   
                       │                                     │                              
  Updated base image   │  python:3.13-slim                   │    0C     0H     2M    20L   
                       │                                     │                              

What's next:
    View vulnerabilities → docker scout cves getwilds/gtf-smash:latest
    View base image update recommendations → docker scout recommendations getwilds/gtf-smash:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/gtf-smash:latest --org <organization>
```
</details>
