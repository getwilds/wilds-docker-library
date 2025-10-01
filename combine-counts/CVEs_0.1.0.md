# Vulnerability Report for getwilds/combine-counts:0.1.0

Report generated on 2025-10-01 09:22:26 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 12 |
| 🟢 Low | 12 |
| ⚪ Unknown | 1 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 12 |
| 🟢 Low | 12 |

## 🔄 Recommendations

**Refreshed base image:** `python:3.12-slim`

**Updated base image:** `python:3.13.7-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/combine-counts:0.1.0  │    0C     3H    12M    12L     1?   
    digest             │  c3e071a4da5b                           │                                     
  Base image           │  python:3.12-slim                       │    0C     3H    12M    12L     1?   
  Refreshed base image │  python:3.12-slim                       │    0C     1H     2M    22L          
                       │                                         │           -2    -10    +10     -1   
  Updated base image   │  python:3.13.7-slim                     │    0C     1H     2M    22L          
                       │                                         │           -2    -10    +10     -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/combine-counts:0.1.0
    View base image update recommendations → docker scout recommendations getwilds/combine-counts:0.1.0
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/combine-counts:0.1.0 --org <organization>
```
</details>
