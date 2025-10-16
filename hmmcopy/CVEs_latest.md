# Vulnerability Report for getwilds/hmmcopy:latest

Report generated on 2025-10-06 17:05:06 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 2 |
| 🟢 Low | 0 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:20.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 1 |
| 🟢 Low | 0 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/hmmcopy:latest-amd64  │    0C     0H     2M     0L   
    digest           │  ec4707662c0f                           │                              
  Base image         │  ubuntu:20.04                           │    0C     0H     1M     0L   
  Updated base image │  ubuntu:25.10                           │    0C     0H     0M     0L   
                     │                                         │                  -1          

What's next:
    View vulnerabilities → docker scout cves getwilds/hmmcopy:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/hmmcopy:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/hmmcopy:latest-amd64 --org <organization>
```
</details>
