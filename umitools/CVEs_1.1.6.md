# Vulnerability Report for getwilds/umitools:1.1.6

Report generated on 2025-12-01 08:13:12 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 8 |
| 🟡 Medium | 6 |
| 🟢 Low | 171 |
| ⚪ Unknown | 4 |

## 🐳 Base Image

**Image:** `python:3.12-bookworm`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 8 |
| 🟡 Medium | 6 |
| 🟢 Low | 171 |

## 🔄 Recommendations

**Refreshed base image:** `python:3.12-bookworm`

**Updated base image:** `python:3.14-bookworm`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/umitools:1.1.6  │    0C     8H     6M   171L     4?   
    digest             │  2d40b00c6b4d                     │                                     
  Base image           │  python:3.12-bookworm             │    0C     8H     6M   171L     4?   
  Refreshed base image │  python:3.12-bookworm             │    0C     2H     6M   166L     4?   
                       │                                   │           -6            -5          
  Updated base image   │  python:3.14-bookworm             │    0C     2H     6M   166L     4?   
                       │                                   │           -6            -5          

What's next:
    View vulnerabilities → docker scout cves getwilds/umitools:1.1.6
    View base image update recommendations → docker scout recommendations getwilds/umitools:1.1.6
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/umitools:1.1.6 --org <organization>
```
</details>
