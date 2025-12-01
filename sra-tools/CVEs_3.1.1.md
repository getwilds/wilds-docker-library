# Vulnerability Report for getwilds/sra-tools:3.1.1

Report generated on 2025-12-01 08:52:07 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 18 |
| 🟢 Low | 5 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:20.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 5 |
| 🟢 Low | 0 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/sra-tools:3.1.1  │    0C     2H    18M     5L   
    digest           │  857c281722de                      │                              
  Base image         │  ubuntu:20.04                      │    0C     0H     5M     0L   
  Updated base image │  ubuntu:26.04                      │    0C     0H     0M     0L   
                     │                                    │                  -5          

What's next:
    View vulnerabilities → docker scout cves getwilds/sra-tools:3.1.1
    View base image update recommendations → docker scout recommendations getwilds/sra-tools:3.1.1
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/sra-tools:3.1.1 --org <organization>
```
</details>
