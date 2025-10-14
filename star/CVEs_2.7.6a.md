# Vulnerability Report for getwilds/star:2.7.6a

Report generated on 2025-10-08 00:17:45 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 1080 |
| 🟢 Low | 36 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 3 |
| 🟢 Low | 5 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:25.10`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/star:2.7.6a-amd64  │    0C     2H   1080M    36L   
    digest           │  e98e3304ecd5                        │                               
  Base image         │  ubuntu:24.04                        │    0C     0H     3M     5L    
  Updated base image │  ubuntu:25.10                        │    0C     0H     0M     0L    
                     │                                      │                  -3     -5    

What's next:
    View vulnerabilities → docker scout cves getwilds/star:2.7.6a-amd64
    View base image update recommendations → docker scout recommendations getwilds/star:2.7.6a-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/star:2.7.6a-amd64 --org <organization>
```
</details>
