# Vulnerability Report for getwilds/cnvkit:0.9.10

Report generated on 2025-10-01 08:48:24 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 3 |
| 🟢 Low | 79 |
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

**Updated base image:** `python:3.13.7-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/cnvkit:0.9.10  │    0C     5H     3M    79L   
    digest           │  fd76854bd483                    │                              
  Base image         │  python:3.10-slim                │    0C     3H     3M    22L   
  Updated base image │  python:3.13.7-slim              │    0C     1H     2M    22L   
                     │                                  │           -2     -1          

What's next:
    View vulnerabilities → docker scout cves getwilds/cnvkit:0.9.10
    View base image update recommendations → docker scout recommendations getwilds/cnvkit:0.9.10
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/cnvkit:0.9.10 --org <organization>
```
</details>
