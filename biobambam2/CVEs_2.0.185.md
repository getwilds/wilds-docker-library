# Vulnerability Report for getwilds/biobambam2:2.0.185

Report generated on 2025-10-02 03:01:40 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 19 |
| 🟢 Low | 8 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 20 |
| 🟢 Low | 8 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:25.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/biobambam2:2.0.185-amd64  │    0C     0H    19M     8L   
    digest             │  82d280fceb4c                               │                              
  Base image           │  ubuntu:24.04                               │    0C     0H    20M     8L   
  Refreshed base image │  ubuntu:24.04                               │    0C     0H     5M     6L   
                       │                                             │                 -15     -2   
  Updated base image   │  ubuntu:25.04                               │    0C     0H     7M     6L   
                       │                                             │                 -13     -2   

What's next:
    View vulnerabilities → docker scout cves getwilds/biobambam2:2.0.185-amd64
    View base image update recommendations → docker scout recommendations getwilds/biobambam2:2.0.185-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/biobambam2:2.0.185-amd64 --org <organization>
```
</details>
