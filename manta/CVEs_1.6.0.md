# Vulnerability Report for getwilds/manta:1.6.0

Report generated on 2025-12-01 09:08:17 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 2 |
| 🟢 Low | 0 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `python:2-slim`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 2 |
| 🟢 Low | 0 |

## 🔄 Recommendations

**Updated base image:** `python:3-slim`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/manta:1.6.0  │    0C     5H     2M     0L   
    digest           │  9284b1251a67                  │                              
  Base image         │  python:2-slim                 │    0C     5H     2M     0L   
  Updated base image │  python:3-slim                 │    0C     0H     2M    20L   
                     │                                │           -5           +20   

What's next:
    View vulnerabilities → docker scout cves getwilds/manta:1.6.0
    View base image update recommendations → docker scout recommendations getwilds/manta:1.6.0
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/manta:1.6.0 --org <organization>
```
</details>
