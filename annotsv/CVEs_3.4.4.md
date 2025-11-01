# Vulnerability Report for getwilds/annotsv:3.4.4

Report generated on 2025-11-01 09:04:22 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 22 |
| 🟠 High | 103 |
| 🟡 Medium | 63 |
| 🟢 Low | 23 |
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
Target             │  getwilds/annotsv:3.4.4  │   22C   103H    63M    23L   
    digest           │  af7c6ae4010b                    │                              
  Base image         │  ubuntu:22.04                    │    0C     0H     2M    12L   
  Updated base image │  ubuntu:24.04                    │    0C     0H     2M     5L   
                     │                                  │                         -7   

What's next:
    View vulnerabilities → docker scout cves getwilds/annotsv:3.4.4
    View base image update recommendations → docker scout recommendations getwilds/annotsv:3.4.4
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/annotsv:3.4.4 --org <organization>
```
</details>
