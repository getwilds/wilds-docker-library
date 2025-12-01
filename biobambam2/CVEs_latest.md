# Vulnerability Report for getwilds/biobambam2:latest

Report generated on 2025-12-01 08:50:55 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 26 |
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
Target               │  getwilds/biobambam2:latest  │    0C     0H    26M     8L   
    digest             │  7e04bce63c13                        │                              
  Base image           │  ubuntu:24.04                        │    0C     0H    20M     8L   
  Refreshed base image │  ubuntu:24.04                        │    0C     0H     2M     5L   
                       │                                      │                 -18     -3   
  Updated base image   │  ubuntu:25.04                        │    0C     0H     2M     4L   
                       │                                      │                 -18     -4   

What's next:
    View vulnerabilities → docker scout cves getwilds/biobambam2:latest
    View base image update recommendations → docker scout recommendations getwilds/biobambam2:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/biobambam2:latest --org <organization>
```
</details>
