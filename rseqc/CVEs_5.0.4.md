# Vulnerability Report for getwilds/rseqc:5.0.4

Report generated on 2025-11-05 06:32:32 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 3 |
| 🟢 Low | 62 |
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

**Updated base image:** `python:3.13-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/rseqc:5.0.4-amd64  │    0C     0H     3M    62L   
    digest           │  6eaa0b86eaaf                        │                              
  Base image         │  python:3.12-slim                    │    0C     0H     2M    20L   
  Updated base image │  python:3.13-slim                    │    0C     0H     2M    20L   
                     │                                      │                              

What's next:
    View vulnerabilities → docker scout cves getwilds/rseqc:5.0.4-amd64
    View base image update recommendations → docker scout recommendations getwilds/rseqc:5.0.4-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/rseqc:5.0.4-amd64 --org <organization>
```
</details>
