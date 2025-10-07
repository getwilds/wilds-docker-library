# Vulnerability Report for getwilds/strelka:2.9.10

Report generated on 2025-10-07 21:04:09 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |
| 🟡 Medium | 1309 |
| 🟢 Low | 65 |
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

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/strelka:2.9.10-amd64  │    0C     1H   1309M    65L   
    digest           │  978adc961271                           │                               
  Base image         │  ubuntu:22.04                           │    0C     0H     2M    12L    
  Updated base image │  ubuntu:25.10                           │    0C     0H     0M     0L    
                     │                                         │                  -2    -12    

What's next:
    View vulnerabilities → docker scout cves getwilds/strelka:2.9.10-amd64
    View base image update recommendations → docker scout recommendations getwilds/strelka:2.9.10-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/strelka:2.9.10-amd64 --org <organization>
```
</details>
