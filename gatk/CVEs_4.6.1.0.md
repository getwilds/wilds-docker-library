# Vulnerability Report for getwilds/gatk:4.6.1.0

Report generated on 2025-10-01 08:20:05 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 18 |
| 🟡 Medium | 1303 |
| 🟢 Low | 58 |
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
Target               │  getwilds/gatk:4.6.1.0  │    1C    18H   1303M    58L   
    digest             │  08efdb45ecc3                   │                               
  Base image           │  ubuntu:24.04                   │    0C     0H     6M     6L    
  Refreshed base image │  ubuntu:24.04                   │    0C     0H     5M     6L    
                       │                                 │                  -1           
  Updated base image   │  ubuntu:25.10                   │    0C     0H     0M     0L    
                       │                                 │                  -6     -6    

What's next:
    View vulnerabilities → docker scout cves getwilds/gatk:4.6.1.0
    View base image update recommendations → docker scout recommendations getwilds/gatk:4.6.1.0
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/gatk:4.6.1.0 --org <organization>
```
</details>
