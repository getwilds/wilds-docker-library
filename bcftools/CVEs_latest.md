# Vulnerability Report for getwilds/bcftools:latest

Report generated on 2025-10-01 08:15:45 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 1260 |
| 🟢 Low | 39 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 6 |
| 🟢 Low | 6 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/bcftools:latest  │    0C     3H   1260M    39L   
    digest             │  ec8b131c6873                      │                               
  Base image           │  ubuntu:24.04                      │    0C     0H     6M     6L    
  Refreshed base image │  ubuntu:24.04                      │    0C     0H     5M     6L    
                       │                                    │                  -1           
  Updated base image   │  ubuntu:25.10                      │    0C     0H     0M     0L    
                       │                                    │                  -6     -6    

What's next:
    View vulnerabilities → docker scout cves getwilds/bcftools:latest
    View base image update recommendations → docker scout recommendations getwilds/bcftools:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bcftools:latest --org <organization>
```
</details>
