# Vulnerability Report for getwilds/picard:latest

Report generated on 2025-10-16 05:51:57 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 9 |
| 🟢 Low | 21 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 5 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/picard:latest-amd64  │    0C     2H     9M    21L   
    digest           │  ff5a9864d8c1                          │                              
  Base image         │  ubuntu:24.04                          │    0C     0H     2M     5L   
  Updated base image │  ubuntu:25.04                          │    0C     0H     2M     4L   
                     │                                        │                         -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/picard:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/picard:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/picard:latest-amd64 --org <organization>
```
</details>
