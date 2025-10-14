# Vulnerability Report for getwilds/awscli:latest

Report generated on 2025-10-01 23:01:18 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 7 |
| 🟡 Medium | 21 |
| 🟢 Low | 11 |
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

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/awscli:latest-amd64  │    3C     7H    21M    11L   
    digest             │  e6cbfa5742ee                          │                              
  Base image           │  ubuntu:24.04                          │    0C     0H     5M     6L   
  Refreshed base image │  ubuntu:24.04                          │    0C     0H     5M     6L   
                       │                                        │                              
  Updated base image   │  ubuntu:25.10                          │    0C     0H     0M     0L   
                       │                                        │                  -5     -6   

What's next:
    View vulnerabilities → docker scout cves getwilds/awscli:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/awscli:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/awscli:latest-amd64 --org <organization>
```
</details>
