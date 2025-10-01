# Vulnerability Report for getwilds/strelka:2.9.10

Report generated on 2025-10-01 09:50:12 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 1454 |
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

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/strelka:2.9.10  │    0C     2H   1454M    66L   
    digest             │  0a8251054025                     │                               
  Base image           │  ubuntu:22.04                     │    0C     0H     4M    14L    
  Refreshed base image │  ubuntu:22.04                     │    0C     0H     4M    13L    
                       │                                   │                         -1    
  Updated base image   │  ubuntu:25.10                     │    0C     0H     0M     0L    
                       │                                   │                  -4    -14    

What's next:
    View vulnerabilities → docker scout cves getwilds/strelka:2.9.10
    View base image update recommendations → docker scout recommendations getwilds/strelka:2.9.10
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/strelka:2.9.10 --org <organization>
```
</details>
