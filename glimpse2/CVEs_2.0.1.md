# Vulnerability Report for getwilds/glimpse2:2.0.1

Report generated on 2026-03-26 04:37:46 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 5 |
| 🟡 Medium | 1488 |
| 🟢 Low | 64 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 4 |
| 🟢 Low | 11 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/glimpse2:2.0.1  │    1C     5H   1488M    64L  
   digest           │  ce68b644cacd                     │                              
 Base image         │  ubuntu:22.04                     │    0C     0H     4M    11L   
 Updated base image │  ubuntu:24.04                     │    0C     0H     4M     4L   
                    │                                   │                         -7   

What's next:
    View vulnerabilities → docker scout cves getwilds/glimpse2:2.0.1
    View base image update recommendations → docker scout recommendations getwilds/glimpse2:2.0.1
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/glimpse2:2.0.1 --org <organization>
```
</details>
