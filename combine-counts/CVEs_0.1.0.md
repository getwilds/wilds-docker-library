# Vulnerability Report for getwilds/combine-counts:0.1.0

Report generated on 2025-12-01 09:15:38 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 4 |
| 🟡 Medium | 12 |
| 🟢 Low | 13 |
| ⚪ Unknown | 1 |

## 🐳 Base Image

**Image:** `python:3.12-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 4 |
| 🟡 Medium | 12 |
| 🟢 Low | 13 |

## 🔄 Recommendations

**Refreshed base image:** `python:3.12-slim`

**Updated base image:** `python:3.14-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/combine-counts:0.1.0  │    0C     4H    12M    13L     1?   
    digest             │  c3e071a4da5b                           │                                     
  Base image           │  python:3.12-slim                       │    0C     4H    12M    13L     1?   
  Refreshed base image │  python:3.12-slim                       │    0C     0H     2M    20L          
                       │                                         │           -4    -10     +7     -1   
  Updated base image   │  python:3.14-slim                       │    0C     0H     2M    20L          
                       │                                         │           -4    -10     +7     -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/combine-counts:0.1.0
    View base image update recommendations → docker scout recommendations getwilds/combine-counts:0.1.0
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/combine-counts:0.1.0 --org <organization>
```
</details>
