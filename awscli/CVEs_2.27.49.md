# Vulnerability Report for getwilds/awscli:2.27.49

Report generated on 2025-10-01 09:36:21 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 7 |
| 🟡 Medium | 22 |
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
Target               │  getwilds/awscli:2.27.49  │    3C     7H    22M    11L   
    digest             │  6758c65164d0                     │                              
  Base image           │  ubuntu:24.04                     │    0C     0H     5M     6L   
  Refreshed base image │  ubuntu:24.04                     │    0C     0H     5M     6L   
                       │                                   │                              
  Updated base image   │  ubuntu:25.10                     │    0C     0H     0M     0L   
                       │                                   │                  -5     -6   

What's next:
    View vulnerabilities → docker scout cves getwilds/awscli:2.27.49
    View base image update recommendations → docker scout recommendations getwilds/awscli:2.27.49
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/awscli:2.27.49 --org <organization>
```
</details>
