# Vulnerability Report for getwilds/cellranger:latest

Report generated on 2025-11-01 09:48:53 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 8 |
| 🟠 High | 87 |
| 🟡 Medium | 3580 |
| 🟢 Low | 89 |
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
Target               │  getwilds/cellranger:latest  │    8C    87H   3580M    89L     2?   
    digest             │  886b9b9a85f0                        │                                      
  Base image           │  ubuntu:24.04                        │    0C     0H    34M    17L           
  Refreshed base image │  ubuntu:24.04                        │    0C     0H     2M     5L           
                       │                                      │                 -32    -12           
  Updated base image   │  ubuntu:25.10                        │    0C     0H     0M     0L           
                       │                                      │                 -34    -17           

What's next:
    View vulnerabilities → docker scout cves getwilds/cellranger:latest
    View base image update recommendations → docker scout recommendations getwilds/cellranger:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/cellranger:latest --org <organization>
```
</details>
