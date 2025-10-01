# Vulnerability Report for getwilds/umitools:latest

Report generated on 2025-10-01 08:12:08 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 7 |
| 🟡 Medium | 4 |
| 🟢 Low | 158 |
| ⚪ Unknown | 4 |

## 🐳 Base Image

**Image:** `python:3.12-bookworm`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 6 |
| 🟡 Medium | 4 |
| 🟢 Low | 158 |

## 🔄 Recommendations

**Updated base image:** `python:3.13-bookworm`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/umitools:latest  │    0C     7H     4M   158L     4?   
    digest           │  06854ebcdc2e                      │                                     
  Base image         │  python:3.12-bookworm              │    0C     6H     4M   158L     4?   
  Updated base image │  python:3.13-bookworm              │    0C     6H     4M   158L     4?   
                     │                                    │                                     

What's next:
    View vulnerabilities → docker scout cves getwilds/umitools:latest
    View base image update recommendations → docker scout recommendations getwilds/umitools:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/umitools:latest --org <organization>
```
</details>
