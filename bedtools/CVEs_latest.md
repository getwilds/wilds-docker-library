# Vulnerability Report for getwilds/bedtools:latest

Report generated on 2025-09-25 03:59:57 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 1087 |
| 🟢 Low | 36 |
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

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/bedtools:latest-amd64  │    0C     2H   1087M    36L   
    digest           │  2160b5273477                            │                               
  Base image         │  ubuntu:24.04                            │    0C     0H     5M     6L    
  Updated base image │  ubuntu:25.04                            │    0C     0H     5M     5L    
                     │                                          │                         -1    

What's next:
    View vulnerabilities → docker scout cves getwilds/bedtools:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/bedtools:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bedtools:latest-amd64 --org <organization>
```
</details>
