# Vulnerability Report for getwilds/manta:1.6.0

Report generated on 2025-10-06 19:42:31 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 2 |
| 🟢 Low | 0 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `python:2-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 2 |
| 🟢 Low | 0 |

## 🔄 Recommendations

**Updated base image:** `python:3.9-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/manta:1.6.0-amd64  │    0C     5H     2M     0L   
    digest           │  46bc7a7865d4                        │                              
  Base image         │  python:2-slim                       │    0C     5H     2M     0L   
  Updated base image │  python:3.9-slim                     │    0C     4H     3M    22L   
                     │                                      │           -1     +1    +22   

What's next:
    View vulnerabilities → docker scout cves getwilds/manta:1.6.0-amd64
    View base image update recommendations → docker scout recommendations getwilds/manta:1.6.0-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/manta:1.6.0-amd64 --org <organization>
```
</details>
