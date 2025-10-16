# Vulnerability Report for getwilds/umitools:1.1.6

Report generated on 2025-10-07 22:21:07 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 5 |
| 🟢 Low | 158 |
| ⚪ Unknown | 4 |

## 🐳 Base Image

**Image:** `python:3.12-bookworm`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 4 |
| 🟢 Low | 158 |

## 🔄 Recommendations

**Updated base image:** `python:3.13-bookworm`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/umitools:1.1.6-amd64  │    0C     3H     5M   158L     4?   
    digest           │  01dd7372cbdb                           │                                     
  Base image         │  python:3.12-bookworm                   │    0C     3H     4M   158L     4?   
  Updated base image │  python:3.13-bookworm                   │    0C     3H     4M   158L     4?   
                     │                                         │                                     

What's next:
    View vulnerabilities → docker scout cves getwilds/umitools:1.1.6-amd64
    View base image update recommendations → docker scout recommendations getwilds/umitools:1.1.6-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/umitools:1.1.6-amd64 --org <organization>
```
</details>
