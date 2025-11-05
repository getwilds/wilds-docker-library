# Vulnerability Report for getwilds/bedops:2.4.42

Report generated on 2025-11-05 22:38:36 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 10 |
| 🟢 Low | 6 |
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
Target             │  getwilds/bedops:2.4.42-amd64  │    0C     0H    10M     6L   
    digest           │  457f61a39300                          │                              
  Base image         │  ubuntu:24.04                          │    0C     0H     2M     5L   
  Updated base image │  ubuntu:25.04                          │    0C     0H     2M     4L   
                     │                                        │                         -1   

What's next:
    View vulnerabilities → docker scout cves getwilds/bedops:2.4.42-amd64
    View base image update recommendations → docker scout recommendations getwilds/bedops:2.4.42-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/bedops:2.4.42-amd64 --org <organization>
```
</details>
