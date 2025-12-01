# Vulnerability Report for getwilds/bedops:latest

Report generated on 2025-12-01 09:08:43 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 6 |
| 🟢 Low | 7 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 5 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/bedops:latest  │    0C     0H     6M     7L   
    digest             │  23a2102ca800                    │                              
  Base image           │  ubuntu:24.04                    │    0C     0H     2M     5L   
  Refreshed base image │  ubuntu:24.04                    │    0C     0H     2M     5L   
                       │                                  │                              
  Updated base image   │  ubuntu:25.04                    │    0C     0H     2M     4L   
                       │                                  │                         -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/bedops:latest
    View base image update recommendations → docker scout recommendations getwilds/bedops:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bedops:latest --org <organization>
```
</details>
