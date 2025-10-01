# Vulnerability Report for getwilds/consensus:0.1.1

Report generated on 2025-10-01 08:23:03 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 0 |
| 🟢 Low | 0 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `debian:9`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 0 |
| 🟢 Low | 0 |

## 🔄 Recommendations

**Updated base image:** `debian:12-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/consensus:0.1.1  │    0C     3H     0M     0L   
    digest           │  f1de8d623928                      │                              
  Base image         │  debian:9                          │    0C     0H     0M     0L   
  Updated base image │  debian:12-slim                    │    0C     0H     1M    24L   
                     │                                    │                  +1    +24   

What's next:
    View vulnerabilities → docker scout cves getwilds/consensus:0.1.1
    View base image update recommendations → docker scout recommendations getwilds/consensus:0.1.1
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/consensus:0.1.1 --org <organization>
```
</details>
