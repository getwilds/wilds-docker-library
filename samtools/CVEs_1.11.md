# Vulnerability Report for getwilds/samtools:1.11

Report generated on 2025-10-14 03:29:04 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |
| 🟡 Medium | 1123 |
| 🟢 Low | 36 |
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

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/samtools:1.11  │    0C     1H   1123M    36L   
    digest           │  4c1e44818702                    │                               
  Base image         │  ubuntu:24.04                    │    0C     0H     2M     5L    
  Updated base image │  ubuntu:25.04                    │    0C     0H     2M     4L    
                     │                                  │                         -1    

What's next:
    View vulnerabilities → docker scout cves getwilds/samtools:1.11
    View base image update recommendations → docker scout recommendations getwilds/samtools:1.11
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/samtools:1.11 --org <organization>
```
</details>
