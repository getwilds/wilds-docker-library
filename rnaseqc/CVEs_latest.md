# Vulnerability Report for getwilds/rnaseqc:latest

Report generated on 2025-10-06 21:26:20 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 6 |
| 🟢 Low | 20 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 3 |
| 🟢 Low | 5 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/rnaseqc:latest-amd64  │    0C     0H     6M    20L   
    digest           │  56c96775368a                           │                              
  Base image         │  ubuntu:24.04                           │    0C     0H     3M     5L   
  Updated base image │  ubuntu:25.10                           │    0C     0H     0M     0L   
                     │                                         │                  -3     -5   

What's next:
    View vulnerabilities → docker scout cves getwilds/rnaseqc:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/rnaseqc:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/rnaseqc:latest-amd64 --org <organization>
```
</details>
