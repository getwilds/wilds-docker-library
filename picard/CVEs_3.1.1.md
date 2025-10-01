# Vulnerability Report for getwilds/picard:3.1.1

Report generated on 2025-10-01 09:35:15 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 52 |
| 🟢 Low | 24 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 14 |
| 🟢 Low | 6 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/picard:3.1.1  │    0C     3H    52M    24L   
    digest             │  ece227274221                   │                              
  Base image           │  ubuntu:24.04                   │    0C     0H    14M     6L   
  Refreshed base image │  ubuntu:24.04                   │    0C     0H     5M     6L   
                       │                                 │                  -9          
  Updated base image   │  ubuntu:25.04                   │    0C     0H     7M     6L   
                       │                                 │                  -7          

What's next:
    View vulnerabilities → docker scout cves getwilds/picard:3.1.1
    View base image update recommendations → docker scout recommendations getwilds/picard:3.1.1
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/picard:3.1.1 --org <organization>
```
</details>
