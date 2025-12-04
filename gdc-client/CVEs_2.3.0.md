# Vulnerability Report for getwilds/gdc-client:2.3.0

Report generated on 2025-12-04 17:30:39 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |
| 🟡 Medium | 6 |
| 🟢 Low | 8 |
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

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/gdc-client:2.3.0-amd64  │    0C     2H     6M     8L   
    digest           │  9bfeb02d145d                             │                              
  Base image         │  ubuntu:24.04                             │    0C     0H     2M     5L   
  Updated base image │  ubuntu:26.04                             │    0C     0H     0M     0L   
                     │                                           │                  -2     -5   

What's next:
    View vulnerabilities → docker scout cves getwilds/gdc-client:2.3.0-amd64
    View base image update recommendations → docker scout recommendations getwilds/gdc-client:2.3.0-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/gdc-client:2.3.0-amd64 --org <organization>
```
</details>
