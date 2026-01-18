# Vulnerability Report for getwilds/glimpse2:latest

Report generated on 2026-01-18 08:07:31 PST

## Platform Coverage

This vulnerability scan covers the **linux/amd64** platform. While this image also supports linux/arm64, the security analysis focuses on the AMD64 variant as it represents the majority of deployment targets. Vulnerabilities between architectures are typically similar for most bioinformatics applications.

## 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 1585 |
| 🟢 Low | 70 |
| ⚪ Unknown | 0 |

## 🐳 Base Image

**Image:** `ubuntu:22.04`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 4 |
| 🟢 Low | 12 |

## 🔄 Recommendations

**Updated base image:** `ubuntu:24.04`

<details>
<summary>📋 Raw Docker Scout Output</summary>

```text
Target             │  getwilds/glimpse2:latest  │    0C     5H   1585M    70L  
   digest           │  3d56ebf0e3c4                      │                              
 Base image         │  ubuntu:22.04                      │    0C     0H     4M    12L   
 Updated base image │  ubuntu:24.04                      │    0C     0H     3M     4L   
                    │                                    │                  -1     -8   

What's next:
    View vulnerabilities → docker scout cves getwilds/glimpse2:latest
    View base image update recommendations → docker scout recommendations getwilds/glimpse2:latest
    Include policy results in your quickview by supplying an organization → docker scout quickview getwilds/glimpse2:latest --org <organization>
```
</details>
