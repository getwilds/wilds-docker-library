# Vulnerability Report for getwilds/hisat2:latest

Report generated on 2025-10-01 08:21:09 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 7 |
| 🟡 Medium | 1578 |
| 🟢 Low | 42 |
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
Target               │  getwilds/hisat2:latest  │    0C     7H   1578M    42L   
    digest             │  65b2320dbd31                    │                               
  Base image           │  ubuntu:24.04                    │    0C     0H    14M     6L    
  Refreshed base image │  ubuntu:24.04                    │    0C     0H     5M     6L    
                       │                                  │                  -9           
  Updated base image   │  ubuntu:25.04                    │    0C     0H     7M     6L    
                       │                                  │                  -7           

What's next:
    View vulnerabilities → docker scout cves getwilds/hisat2:latest
    View base image update recommendations → docker scout recommendations getwilds/hisat2:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/hisat2:latest --org <organization>
```
</details>
