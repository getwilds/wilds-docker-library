# Vulnerability Report for getwilds/strelka:latest

Report generated on 2025-11-01 09:54:56 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 1242 |
| 🟢 Low | 70 |
| ⚪ Unknown | 0 |

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
Target             │  getwilds/strelka:latest  │    0C     3H   1242M    70L   
    digest           │  6c787777c632                     │                               
  Base image         │  ubuntu:22.04                     │    0C     0H     2M    12L    
  Updated base image │  ubuntu:24.04                     │    0C     0H     2M     5L    
                     │                                   │                         -7    

What's next:
    View vulnerabilities → docker scout cves getwilds/strelka:latest
    View base image update recommendations → docker scout recommendations getwilds/strelka:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/strelka:latest --org <organization>
```
</details>
