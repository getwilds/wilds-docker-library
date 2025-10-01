# Vulnerability Report for getwilds/varscan:latest

Report generated on 2025-10-01 09:53:35 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 1712 |
| 🟢 Low | 83 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 11 |
| 🟢 Low | 14 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/varscan:latest  │    0C     5H   1712M    83L   
    digest             │  d81e80829d15                     │                               
  Base image           │  ubuntu:22.04                     │    0C     0H    11M    14L    
  Refreshed base image │  ubuntu:22.04                     │    0C     0H     4M    13L    
                       │                                   │                  -7     -1    
  Updated base image   │  ubuntu:24.04                     │    0C     0H     5M     6L    
                       │                                   │                  -6     -8    

What's next:
    View vulnerabilities → docker scout cves getwilds/varscan:latest
    View base image update recommendations → docker scout recommendations getwilds/varscan:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/varscan:latest --org <organization>
```
</details>
