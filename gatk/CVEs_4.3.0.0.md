# Vulnerability Report for getwilds/gatk:4.3.0.0

Report generated on 2025-12-01 08:17:01 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 16 |
| 🟠 High | 71 |
| 🟡 Medium | 1388 |
| 🟢 Low | 64 |
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

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/gatk:4.3.0.0  │   16C    71H   1388M    64L   
    digest             │  72b9b124d12f                   │                               
  Base image           │  ubuntu:24.04                   │    0C     0H     6M     6L    
  Refreshed base image │  ubuntu:24.04                   │    0C     0H     2M     5L    
                       │                                 │                  -4     -1    
  Updated base image   │  ubuntu:25.04                   │    0C     0H     2M     4L    
                       │                                 │                  -4     -2    

What's next:
    View vulnerabilities → docker scout cves getwilds/gatk:4.3.0.0
    View base image update recommendations → docker scout recommendations getwilds/gatk:4.3.0.0
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/gatk:4.3.0.0 --org <organization>
```
</details>
