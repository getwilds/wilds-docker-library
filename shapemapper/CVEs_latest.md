# Vulnerability Report for getwilds/shapemapper:latest

Report generated on 2025-12-15 19:46:18 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 17 |
| 🟡 Medium | 23 |
| 🟢 Low | 15 |
| ⚪ Unknown | 2 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 12 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/shapemapper:latest  │    1C    17H    23M    15L     2?   
    digest           │  673a63140676                         │                                     
  Base image         │  ubuntu:22.04                         │    0C     0H     2M    12L          
  Updated base image │  ubuntu:24.04                         │    0C     0H     2M     5L          
                     │                                       │                         -7          

What's next:
    View vulnerabilities → docker scout cves getwilds/shapemapper:latest
    View base image update recommendations → docker scout recommendations getwilds/shapemapper:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/shapemapper:latest --org <organization>
```
</details>
