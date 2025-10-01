# Vulnerability Report for getwilds/cellranger:6.0.2

Report generated on 2025-10-01 09:41:59 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 8 |
| 🟠 High | 74 |
| 🟡 Medium | 3567 |
| 🟢 Low | 84 |
| ⚪ Unknown | 2 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 34 |
| 🟢 Low | 17 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/cellranger:6.0.2  │    8C    74H   3567M    84L     2?   
    digest             │  0dec48219479                       │                                      
  Base image           │  ubuntu:24.04                       │    0C     0H    34M    17L           
  Refreshed base image │  ubuntu:24.04                       │    0C     0H     5M     6L           
                       │                                     │                 -29    -11           
  Updated base image   │  ubuntu:25.10                       │    0C     0H     0M     0L           
                       │                                     │                 -34    -17           

What's next:
    View vulnerabilities → docker scout cves getwilds/cellranger:6.0.2
    View base image update recommendations → docker scout recommendations getwilds/cellranger:6.0.2
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/cellranger:6.0.2 --org <organization>
```
</details>
