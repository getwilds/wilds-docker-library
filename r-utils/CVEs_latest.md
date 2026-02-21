# Vulnerability Report for getwilds/r-utils:latest

Report generated on 2026-02-21 06:55:42 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 10 |
| 🟡 Medium | 1497 |
| 🟢 Low | 62 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:24.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |
| 🟡 Medium | 9 |
| 🟢 Low | 12 |

## 🔄 Recommendations

**Refreshed base image:** `ubuntu:24.04`

**Updated base image:** `ubuntu:26.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target               │  getwilds/r-utils:latest-amd64  │    1C    10H   1497M    62L  
   digest             │  ff3a669fd984                           │                              
 Base image           │  ubuntu:24.04                           │    0C     1H     9M    12L   
 Refreshed base image │  ubuntu:24.04                           │    0C     0H     4M     5L   
                      │                                         │           -1     -5     -7   
 Updated base image   │  ubuntu:26.04                           │    0C     0H     0M     0L   
                      │                                         │           -1     -9    -12   

What's next:
    View vulnerabilities → docker scout cves getwilds/r-utils:latest-amd64
    View base image update recommendations → docker scout recommendations getwilds/r-utils:latest-amd64
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/r-utils:latest-amd64 --org <organization>
```
</details>
