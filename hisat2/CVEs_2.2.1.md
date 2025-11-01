# Vulnerability Report for getwilds/hisat2:2.2.1

Report generated on 2025-11-01 08:19:21 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 1105 |
| 🟢 Low | 36 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 3 |
| 🟢 Low | 5 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/hisat2:2.2.1  │    0C     3H   1105M    36L   
    digest             │  8f904869238e                   │                               
  Base image           │  ubuntu:24.04                   │    0C     0H     3M     5L    
  Refreshed base image │  ubuntu:24.04                   │    0C     0H     2M     5L    
                       │                                 │                  -1           
  Updated base image   │  ubuntu:25.04                   │    0C     0H     2M     4L    
                       │                                 │                  -1     -1    

What's next:
    View vulnerabilities → docker scout cves getwilds/hisat2:2.2.1
    View base image update recommendations → docker scout recommendations getwilds/hisat2:2.2.1
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/hisat2:2.2.1 --org <organization>
```
</details>
