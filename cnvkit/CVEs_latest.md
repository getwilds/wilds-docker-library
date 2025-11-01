# Vulnerability Report for getwilds/cnvkit:latest

Report generated on 2025-11-01 08:43:26 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 3 |
| 🟢 Low | 87 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `python:3.10-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 3 |
| 🟢 Low | 22 |

## 🔄 Recommendations

**Refreshed base image:** `python:3.10-slim`

**Updated base image:** `python:3.14-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/cnvkit:latest  │    0C     5H     3M    87L   
    digest             │  94c3e300a412                    │                              
  Base image           │  python:3.10-slim                │    0C     3H     3M    22L   
  Refreshed base image │  python:3.10-slim                │    0C     0H     3M    20L   
                       │                                  │           -3            -2   
  Updated base image   │  python:3.14-slim                │    0C     0H     2M    20L   
                       │                                  │           -3     -1     -2   

What's next:
    View vulnerabilities → docker scout cves getwilds/cnvkit:latest
    View base image update recommendations → docker scout recommendations getwilds/cnvkit:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/cnvkit:latest --org <organization>
```
</details>
