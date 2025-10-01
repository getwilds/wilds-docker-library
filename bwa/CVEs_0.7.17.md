# Vulnerability Report for getwilds/bwa:0.7.17

Report generated on 2025-10-01 08:38:31 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 1561 |
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
Target               │  getwilds/bwa:0.7.17  │    0C     5H   1561M    42L   
    digest             │  603692068a02                 │                               
  Base image           │  ubuntu:24.04                 │    0C     0H    14M     6L    
  Refreshed base image │  ubuntu:24.04                 │    0C     0H     5M     6L    
                       │                               │                  -9           
  Updated base image   │  ubuntu:25.04                 │    0C     0H     7M     6L    
                       │                               │                  -7           

What's next:
    View vulnerabilities → docker scout cves getwilds/bwa:0.7.17
    View base image update recommendations → docker scout recommendations getwilds/bwa:0.7.17
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bwa:0.7.17 --org <organization>
```
</details>
