# Vulnerability Report for getwilds/shapemapper:latest

Report generated on 2025-10-01 08:52:57 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 17 |
| 🟡 Medium | 49 |
| 🟢 Low | 21 |
| ⚪ Unknown | 2 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 21 |
| 🟢 Low | 18 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:22.04`

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/shapemapper:latest  │    1C    17H    49M    21L     2?   
    digest             │  f0c93f75561d                         │                                     
  Base image           │  ubuntu:22.04                         │    0C     0H    21M    18L          
  Refreshed base image │  ubuntu:22.04                         │    0C     0H     4M    13L          
                       │                                       │                 -17     -5          
  Updated base image   │  ubuntu:24.04                         │    0C     0H     5M     6L          
                       │                                       │                 -16    -12          

What's next:
    View vulnerabilities → docker scout cves getwilds/shapemapper:latest
    View base image update recommendations → docker scout recommendations getwilds/shapemapper:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/shapemapper:latest --org <organization>
```
</details>
