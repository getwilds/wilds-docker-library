# Vulnerability Report for getwilds/awscli:latest

Report generated on 2025-10-16 05:38:02 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 7 |
| 🟡 Medium | 21 |
| 🟢 Low | 12 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 5 |
| 🟢 Low | 6 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/awscli:latest-amd64  │    3C     7H    21M    12L   
    digest             │  f25972119f53                          │                              
  Base image           │  ubuntu:24.04                          │    0C     0H     5M     6L   
  Refreshed base image │  ubuntu:24.04                          │    0C     0H     2M     5L   
                       │                                        │                  -3     -1   
  Updated base image   │  ubuntu:25.04                          │    0C     0H     2M     4L   
                       │                                        │                  -3     -2   

What's next:
    View vulnerabilities → docker scout cves getwilds/awscli:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/awscli:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/awscli:latest-amd64 --org <organization>
```
</details>
