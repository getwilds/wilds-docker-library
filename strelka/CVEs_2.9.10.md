# Vulnerability Report for getwilds/strelka:2.9.10

Report generated on 2025-10-14 03:59:42 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 4 |
| 🟡 Medium | 1360 |
| 🟢 Low | 66 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 4 |
| 🟢 Low | 14 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/strelka:2.9.10  │    0C     4H   1360M    66L   
    digest             │  0a8251054025                     │                               
  Base image           │  ubuntu:22.04                     │    0C     0H     4M    14L    
  Refreshed base image │  ubuntu:22.04                     │    0C     0H     2M    12L    
                       │                                   │                  -2     -2    
  Updated base image   │  ubuntu:24.04                     │    0C     0H     2M     5L    
                       │                                   │                  -2     -9    

What's next:
    View vulnerabilities → docker scout cves getwilds/strelka:2.9.10
    View base image update recommendations → docker scout recommendations getwilds/strelka:2.9.10
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/strelka:2.9.10 --org <organization>
```
</details>
